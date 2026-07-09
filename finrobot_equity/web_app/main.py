import os
import sys
import subprocess
import threading
import uuid
import json
import logging
import hashlib
import secrets
import configparser
import re
import csv
import base64
import httpx
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from urllib.parse import quote
from fastapi import FastAPI, Request, BackgroundTasks, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# ============== GitHub OAuth Configuration ==============
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "YOUR_GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "YOUR_GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = "http://localhost:8000/api/auth/github/callback"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base path for the actual project (nested structure)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_ROOT = os.path.join(PROJECT_ROOT, "core")
SRC_ROOT = CORE_ROOT  # SRC_ROOT points to core directory, scripts are in core/src
OUTPUT_DIR = os.path.join(CORE_ROOT, "output")
CONFIG_DIR = os.path.join(CORE_ROOT, "config")
DATA_DIR = os.path.join(PROJECT_ROOT, "web_app", "data")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")  # 统一日志目录：finrobot_equity/logs/

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)  # 新增：创建日志目录

def ensure_runtime_config():
    """Create the core config.ini from Render environment variables."""
    env_names = [
        "FMP_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "ADANOS_API_KEY",
        "ADANOS_BASE_URL",
        "FINNHUB_API_KEY",
    ]
    config_path = os.path.join(CONFIG_DIR, "config.ini")
    has_env_config = any(os.getenv(name) for name in env_names)

    if os.path.exists(config_path) and not has_env_config:
        return

    os.makedirs(CONFIG_DIR, exist_ok=True)
    config = configparser.ConfigParser()
    config["API_KEYS"] = {
        "fmp_api_key": os.getenv("FMP_API_KEY", "YOUR_FMP_API_KEY"),
        "openai_api_key": os.getenv("OPENAI_API_KEY", "YOUR_OPENAI_API_KEY"),
        "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "openai_model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
        "adanos_api_key": os.getenv("ADANOS_API_KEY", ""),
        "adanos_base_url": os.getenv("ADANOS_BASE_URL", "https://api.adanos.org"),
        "finnhub_api_key": os.getenv("FINNHUB_API_KEY", ""),
    }
    with open(config_path, "w", encoding="utf-8") as f:
        config.write(f)


ensure_runtime_config()

app = FastAPI(title="FinRobot Equity Research", version="1.0.0")

# Mount static files and templates
app.mount("/static", StaticFiles(directory=os.path.join(PROJECT_ROOT, "web_app", "static")), name="static")
app.mount("/output", StaticFiles(directory=OUTPUT_DIR), name="output")
templates = Jinja2Templates(directory=os.path.join(PROJECT_ROOT, "web_app", "templates"))

# ============== Database Integration ==============
from .database.connection import init_db, SessionLocal
from .database import crud
from .database.models import ReportRequest
from .auth import (
    get_current_user, require_auth, create_user_session, delete_user_session,
    authenticate_user, register_user, get_or_create_github_user, 
    change_user_password, init_default_admin
)
from .middleware import RequestLoggerMiddleware
from .admin_routes import router as admin_router

# Initialize database
init_db()
init_default_admin()

# Add middleware for request logging
app.add_middleware(RequestLoggerMiddleware)

# Include admin routes
app.include_router(admin_router)

# Auth Models
class LoginRequest(BaseModel):
    email: str
    password: str
    remember: bool = False

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str

# ============== 日志文件持久化功能 ==============

def get_log_file_path(task_id: str) -> str:
    """获取任务日志文件路径"""
    return os.path.join(LOGS_DIR, f"task_{task_id}.log")

def redact_sensitive_text(message: str) -> str:
    """Redact API keys and bearer-style secrets before logs are persisted or returned."""
    text = str(message or "")
    patterns = [
        (r"(?i)(apikey=)[^&\s]+", r"\1[REDACTED]"),
        (r"(?i)(api_key=)[^&\s]+", r"\1[REDACTED]"),
        (r"(?i)(token=)[^&\s]+", r"\1[REDACTED]"),
        (r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+", r"\1[REDACTED]"),
        (r"\b(sk-[A-Za-z0-9_\-]{12,})\b", "[REDACTED]"),
        (r"\b(rnd_[A-Za-z0-9_\-]{12,})\b", "[REDACTED]"),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text

def write_log_to_file(task_id: str, message: str):
    """将日志写入文件"""
    log_path = get_log_file_path(task_id)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_message = redact_sensitive_text(message)
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {safe_message}\n")
    except Exception as e:
        logger.warning(f"Failed to write log to file: {e}")

def read_log_from_file(task_id: str) -> List[str]:
    """从文件读取日志"""
    log_path = get_log_file_path(task_id)
    if not os.path.exists(log_path):
        return []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            return [redact_sensitive_text(line.strip()) for line in f.readlines()]
    except Exception as e:
        logger.warning(f"Failed to read log from file: {e}")
        return []

def append_task_log(task_id: str, message: str):
    """同时写入内存和文件的日志函数"""
    safe_message = redact_sensitive_text(message)
    # 写入内存
    if task_id in tasks:
        tasks[task_id]["logs"].append(safe_message)
    # 写入文件
    write_log_to_file(task_id, safe_message)

# ============== Auth Routes ==============

@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    user = authenticate_user(req.email, req.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")[:500]
    session_id = create_user_session(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        remember=req.remember
    )
    
    # Set cookie
    max_age = 30 * 24 * 60 * 60 if req.remember else 7 * 24 * 60 * 60
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        max_age=max_age,
        samesite="lax"
    )
    
    return {"success": True, "user": {"email": user.email, "name": user.name}}

@app.post("/api/auth/register")
async def register(req: RegisterRequest, request: Request, response: Response):
    user = register_user(req.email, req.password, req.name)
    
    if not user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Auto login after register
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")[:500]
    session_id = create_user_session(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        max_age=7 * 24 * 60 * 60,
        samesite="lax"
    )
    
    return {"success": True, "user": {"email": user.email, "name": user.name}}

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if session_id:
        delete_user_session(session_id)
    
    response.delete_cookie("session_id")
    return {"success": True}

@app.get("/api/auth/me")
async def get_me(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"email": user["email"], "name": user["name"]}

class ChangePasswordRequest(BaseModel):
    currentPassword: str
    newPassword: str

@app.post("/api/auth/change-password")
async def change_password_route(req: ChangePasswordRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # GitHub users cannot change password
    if user.get("provider") == "github" or user["email"].startswith("github:"):
        raise HTTPException(status_code=400, detail="GitHub users cannot change password")
    
    success = change_user_password(user["id"], req.currentPassword, req.newPassword)
    
    if not success:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    return {"success": True, "message": "Password changed successfully"}

# ============== GitHub OAuth Routes ==============

@app.get("/api/auth/github")
async def github_login():
    """Redirect to GitHub OAuth authorization page"""
    if GITHUB_CLIENT_ID == "YOUR_GITHUB_CLIENT_ID":
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.")
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=user:email"
    )
    return RedirectResponse(url=github_auth_url)

@app.get("/api/auth/github/callback")
async def github_callback(code: str, response: Response):
    """Handle GitHub OAuth callback"""
    if not code:
        raise HTTPException(status_code=400, detail="No code provided")
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI
            },
            headers={"Accept": "application/json"}
        )
        token_data = token_response.json()
        
        if "error" in token_data:
            raise HTTPException(status_code=400, detail=token_data.get("error_description", "Failed to get access token"))
        
        access_token = token_data.get("access_token")
        
        # Get user info from GitHub
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        )
        github_user = user_response.json()
        
        # Get user email (might be private)
        email_response = await client.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        )
        emails = email_response.json()
        
        # Find primary email
        primary_email = None
        for email_obj in emails:
            if email_obj.get("primary"):
                primary_email = email_obj.get("email")
                break
        
        if not primary_email:
            primary_email = github_user.get("email") or f"{github_user['login']}@github.local"
        
        # Create or update user in database
        user = get_or_create_github_user(
            email=primary_email,
            name=github_user.get("name") or github_user.get("login"),
            avatar_url=github_user.get("avatar_url"),
            github_id=github_user.get("id")
        )
        
        # Create session
        session_id = create_user_session(user_id=user.id)
        
        # Create redirect response with cookie
        redirect_response = RedirectResponse(url="/", status_code=302)
        redirect_response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            max_age=7 * 24 * 60 * 60,
            samesite="lax"
        )
        
        return redirect_response

# ============== Page Routes ==============

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    user = get_current_user(request)
    if not user:
        response = RedirectResponse(url="/login", status_code=303)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return templates.TemplateResponse(request, "index.html", {"user": user})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        response = RedirectResponse(url="/", status_code=303)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return templates.TemplateResponse(request, "login.html")

# ============== Chrome DevTools Route ==============

@app.get("/.well-known/appspecific/com.chrome.devtools.json")
async def chrome_devtools():
    """Handle Chrome DevTools configuration request"""
    return Response(content="", status_code=204)

# ============== Task System ==============

# Store tasks in memory
tasks = {}

FEISHU_APP_ID = os.getenv("FEISHU_APP_ID", "")
FEISHU_APP_SECRET = os.getenv("FEISHU_APP_SECRET", "")
FEISHU_VERIFICATION_TOKEN = os.getenv("FEISHU_VERIFICATION_TOKEN", "")
FEISHU_BOT_OPEN_ID = os.getenv("FEISHU_BOT_OPEN_ID", "").strip()
FEISHU_BOT_NAME = os.getenv("FEISHU_BOT_NAME", "FinRobot").strip() or "FinRobot"
FEISHU_DOC_BASE_URL = os.getenv("FEISHU_DOC_BASE_URL", "https://feishu.cn/docx")
FEISHU_WIKI_PARENT_TOKEN = os.getenv("FEISHU_WIKI_PARENT_TOKEN", "")
FEISHU_WIKI_SPACE_ID = os.getenv("FEISHU_WIKI_SPACE_ID", "")
PUBLIC_BASE_URL = os.getenv("FINROBOT_PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL", "")
OBSIDIAN_SYNC_ENABLED = os.getenv("OBSIDIAN_SYNC_ENABLED", "").lower() in {"1", "true", "yes", "on"}
OBSIDIAN_GITHUB_TOKEN = os.getenv("OBSIDIAN_GITHUB_TOKEN") or os.getenv("GITHUB_BACKUP_TOKEN", "")
OBSIDIAN_GITHUB_REPO = os.getenv("OBSIDIAN_GITHUB_REPO", "Mad12345-qw/obsidian-knowledge-sync")
OBSIDIAN_GITHUB_BRANCH = os.getenv("OBSIDIAN_GITHUB_BRANCH", "main")
OBSIDIAN_FINROBOT_FOLDER = os.getenv("OBSIDIAN_FINROBOT_FOLDER", "finrobot-reports").strip("/\\") or "finrobot-reports"
OBSIDIAN_GITHUB_TIMEOUT = float(os.getenv("OBSIDIAN_GITHUB_TIMEOUT_MS", "30000")) / 1000
_FEISHU_BOT_OPEN_ID_CACHE = FEISHU_BOT_OPEN_ID
FINANCIAL_LABEL_ZH = {
    "Revenue": "营收",
    "Cost of Operations": "营业成本",
    "SG&A": "销售及管理费用",
    "Contribution Profit": "贡献利润",
    "Contribution Margin": "贡献利润率",
    "EBITDA": "EBITDA",
    "EBITDA Margin": "EBITDA 利润率",
    "SG&A Margin": "销售及管理费用率",
    "Revenue Growth": "营收增长率",
    "EPS": "每股收益 EPS",
    "PE Ratio": "市盈率 PE",
    "CAGR": "复合年增长率 CAGR",
    "Growth Delta": "增长率变化",
    "Margin Delta": "利润率变化",
    "ticker": "股票代码",
    "Ticker": "股票代码",
    "metrics": "指标",
    "summary": "摘要",
    "revenue_sensitivity": "营收敏感性",
    "margin_sensitivity": "利润率敏感性",
    "confidence_intervals": "置信区间",
}
TEXT_ZH_REPLACEMENTS = {
    "## Sensitivity Analysis Summary": "敏感性分析摘要",
    "### Key Assumptions:": "关键假设：",
    "### Confidence Intervals:": "置信区间：",
    "### Sensitivity Notes:": "敏感性说明：",
    "Revenue Growth": "营收增长率",
    "Revenue growth sensitivity": "营收增长率敏感性",
    "Margin sensitivity": "利润率敏感性",
    "Margin Delta": "利润率变化",
    "Growth Delta": "增长率变化",
    "EBITDA Margin": "EBITDA 利润率",
    "Revenue": "营收",
    "EBITDA": "EBITDA",
    "confidence": "置信度",
    "change in growth rate": "增长率变化",
    "change in EBITDA margin": "EBITDA 利润率变化",
    "Combined effects shown in sensitivity matrix": "组合影响已在敏感性矩阵中展示",
    "Sensitivity Analysis Summary": "敏感性分析摘要",
    "Key Assumptions": "关键假设",
    "Confidence Intervals": "置信区间",
    "Sensitivity Notes": "敏感性说明",
    "N/A": "无数据",
}

class AnalysisRequest(BaseModel):
    ticker: str
    company_name: str
    peers: List[str] = []
    years_limit: int = 5
    revenue_growth_2025: float = 0.05
    revenue_growth_2026: float = 0.06
    revenue_growth_2027: float = 0.04
    margin_improvement: float = 0.01
    generate_text: bool = True
    generate_pdf: bool = True
    generate_html_report: bool = True
    fmp_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    # 新增增强功能选项
    enable_sensitivity_analysis: bool = True
    enable_catalyst_analysis: bool = True
    enable_enhanced_news: bool = True
    enable_enhanced_charts: bool = True
    enable_valuation_analysis: bool = True
    enable_report_text_regeneration: bool = False


def public_url(path: str) -> str:
    if not PUBLIC_BASE_URL:
        return path
    return f"{PUBLIC_BASE_URL.rstrip('/')}/{path.lstrip('/')}"


def slugify_report_part(value: str, fallback: str = "report") -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return (text or fallback)[:80]


TICKER_STOPWORDS = {
    "AI", "API", "APP", "CSV", "DCF", "EV", "FMP", "HTML", "HTTP", "HTTPS", "JSON",
    "LLM", "PDF", "PE", "PEG", "PS", "ROA", "ROE", "ROI", "SEC", "TTM", "URL",
    "VS", "REPORT", "RESEARCH", "ANALYSIS", "FASTREPORT",
}

KNOWN_COMPANY_NAMES = {
    "AAPL": "Apple Inc.",
    "AMZN": "Amazon.com Inc.",
    "BABA": "Alibaba Group Holding Limited",
    "BAC": "Bank of America Corporation",
    "C": "Citigroup Inc.",
    "GOOGL": "Alphabet Inc.",
    "JD": "JD.com Inc.",
    "JPM": "JPMorgan Chase & Co.",
    "META": "Meta Platforms Inc.",
    "MSFT": "Microsoft Corporation",
    "NVDA": "NVIDIA Corporation",
    "PDD": "PDD Holdings Inc",
    "SE": "Sea Limited",
    "TSLA": "Tesla Inc.",
    "WFC": "Wells Fargo & Company",
}

COMPANY_ALIAS_TICKERS = {
    "Alphabet": "GOOGL",
    "Facebook": "META",
    "Google": "GOOGL",
    "Meta": "META",
    "Sea Limited": "SE",
    "Shopee": "SE",
    "亚马逊": "AMZN",
    "京东": "JD",
    "微软": "MSFT",
    "摩根大通": "JPM",
    "拼多多": "PDD",
    "特斯拉": "TSLA",
    "美国银行": "BAC",
    "英伟达": "NVDA",
    "苹果": "AAPL",
    "花旗": "C",
    "谷歌": "GOOGL",
    "阿里": "BABA",
    "阿里巴巴": "BABA",
}


def extract_tickers_from_text(value: str) -> List[str]:
    tickers = []
    for match in re.finditer(r"(?<![A-Za-z0-9.\-])([A-Za-z][A-Za-z0-9.\-]{0,9})(?![A-Za-z0-9.\-])", value or ""):
        raw_ticker = match.group(1)
        ticker = raw_ticker.upper().strip(".-")
        if (
            (raw_ticker == raw_ticker.upper() or ticker in KNOWN_COMPANY_NAMES)
            and (len(ticker) > 1 or ticker in KNOWN_COMPANY_NAMES)
            and re.match(r"^[A-Z][A-Z0-9.\-]{0,9}$", ticker)
            and ticker not in TICKER_STOPWORDS
            and ticker not in tickers
        ):
            tickers.append(ticker)
    return tickers


def extract_report_symbols_from_text(value: str) -> List[str]:
    candidates = []
    for match in re.finditer(r"(?<![A-Za-z0-9.\-])([A-Za-z][A-Za-z0-9.\-]{0,9})(?![A-Za-z0-9.\-])", value or ""):
        raw_ticker = match.group(1)
        ticker = raw_ticker.upper().strip(".-")
        if (
            (raw_ticker == raw_ticker.upper() or ticker in KNOWN_COMPANY_NAMES)
            and (len(ticker) > 1 or ticker in KNOWN_COMPANY_NAMES)
            and re.match(r"^[A-Z][A-Z0-9.\-]{0,9}$", ticker)
            and ticker not in TICKER_STOPWORDS
        ):
            candidates.append((match.start(), ticker))

    for alias, ticker in COMPANY_ALIAS_TICKERS.items():
        for match in re.finditer(re.escape(alias), value or "", flags=re.IGNORECASE):
            candidates.append((match.start(), ticker))

    symbols = []
    for _, ticker in sorted(candidates, key=lambda item: item[0]):
        if ticker not in symbols:
            symbols.append(ticker)
    return symbols


def build_analysis_request(ticker: str, company_name: str = "", peers: Optional[List[str]] = None) -> Optional[AnalysisRequest]:
    ticker = re.sub(r"[^A-Za-z0-9.\-]", "", ticker or "").upper()
    if not re.match(r"^[A-Z][A-Z0-9.\-]{0,9}$", ticker):
        return None

    clean_peers = []
    for peer in peers or []:
        peer_ticker = re.sub(r"[^A-Za-z0-9.\-]", "", peer or "").upper()
        if (
            re.match(r"^[A-Z][A-Z0-9.\-]{0,9}$", peer_ticker)
            and peer_ticker != ticker
            and peer_ticker not in clean_peers
            and peer_ticker not in TICKER_STOPWORDS
        ):
            clean_peers.append(peer_ticker)

    return AnalysisRequest(
        ticker=ticker,
        company_name=(company_name or KNOWN_COMPANY_NAMES.get(ticker) or ticker).strip(),
        peers=clean_peers,
        generate_text=True,
        generate_pdf=False,
        generate_html_report=True,
        enable_enhanced_news=True,
    )


def parse_command_report_request(clean_text: str, lower_text: str) -> Optional[AnalysisRequest]:
    for prefix in ("/fastreport", "fastreport", "/report", "report"):
        if lower_text.startswith(prefix):
            command_text = clean_text[len(prefix):].strip()
            if not command_text:
                return None

            command_parts = [part.strip() for part in command_text.split("|", 1)]
            company_part = command_parts[0]
            peer_part = command_parts[1] if len(command_parts) > 1 else ""
            tokens = company_part.split()
            if not tokens:
                return None

            ticker = re.sub(r"[^A-Za-z0-9.\-]", "", tokens[0]).upper()
            company_name = " ".join(tokens[1:]).strip()
            peers = extract_report_symbols_from_text(peer_part)
            return build_analysis_request(ticker, company_name, peers)
    return None


def parse_natural_report_request(clean_text: str) -> Optional[AnalysisRequest]:
    if not re.search(
        r"(研报|投研|研究报告|报告|分析|估值|同行|对比|比较|竞品|report|research|analysis|valuation|compare|peer|peers)",
        clean_text,
        flags=re.IGNORECASE,
    ):
        return None

    symbols = extract_report_symbols_from_text(clean_text)
    if not symbols:
        return None

    ticker = symbols[0]
    peer_text = ""
    peer_match = re.search(r"(?:\||同行|对比|比较|竞品|peer(?:s)?|vs\.?|versus)[：:\s]*(.+)$", clean_text, flags=re.IGNORECASE)
    if peer_match:
        peer_text = peer_match.group(1)

    peers = extract_report_symbols_from_text(peer_text) if peer_text else symbols[1:]
    return build_analysis_request(ticker, KNOWN_COMPANY_NAMES.get(ticker, ticker), peers)


def parse_feishu_report_request(text: str) -> Optional[AnalysisRequest]:
    clean_text = re.sub(r"<at[^>]*>.*?</at>", "", text or "", flags=re.IGNORECASE).strip()
    lower_text = clean_text.lower()

    if not clean_text or lower_text in {"/help", "help"}:
        return None

    return parse_command_report_request(clean_text, lower_text) or parse_natural_report_request(clean_text)


async def get_feishu_tenant_access_token() -> Optional[str]:
    if not FEISHU_APP_ID or not FEISHU_APP_SECRET:
        return None

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
            json={"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET},
        )
        response.raise_for_status()
        data = response.json()
        return data.get("tenant_access_token")


async def get_feishu_bot_open_id() -> str:
    """Return the app bot open_id when available."""
    global _FEISHU_BOT_OPEN_ID_CACHE
    if _FEISHU_BOT_OPEN_ID_CACHE:
        return _FEISHU_BOT_OPEN_ID_CACHE

    try:
        token = await get_feishu_tenant_access_token()
        if not token:
            return ""

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://open.feishu.cn/open-apis/bot/v3/info",
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code >= 400:
                logger.warning(
                    "Feishu bot info failed: status=%s body=%s",
                    response.status_code,
                    response.text[:1000],
                )
                return ""
            data = response.json()
    except Exception as e:
        logger.warning(f"Failed to fetch Feishu bot info: {e}")
        return ""

    bot_info = data.get("bot") or data.get("data", {}).get("bot") or data.get("data", {})
    open_id = (bot_info or {}).get("open_id") or (bot_info or {}).get("bot_open_id") or ""
    if open_id:
        _FEISHU_BOT_OPEN_ID_CACHE = open_id
    return open_id


def _mention_ids(mention: Dict) -> List[str]:
    ids = []
    mention_id = mention.get("id")
    if isinstance(mention_id, dict):
        ids.extend(str(value) for value in mention_id.values() if value)
    elif mention_id:
        ids.append(str(mention_id))

    for key in ("open_id", "user_id", "union_id", "tenant_key"):
        value = mention.get(key)
        if value:
            ids.append(str(value))
    return ids


def feishu_message_mentions_bot(message: Dict, bot_open_id: str = "") -> bool:
    mentions = message.get("mentions") or []
    raw_message = json.dumps(message, ensure_ascii=False)

    for mention in mentions:
        mention_ids = _mention_ids(mention)
        if bot_open_id and bot_open_id in mention_ids:
            return True

        mention_name = str(
            mention.get("name")
            or mention.get("text")
            or mention.get("mention_name")
            or mention.get("display_name")
            or ""
        ).lstrip("@")
        if mention_name and mention_name.lower() == FEISHU_BOT_NAME.lower():
            return True

    if bot_open_id and bot_open_id in raw_message and "<at" in raw_message:
        return True
    if FEISHU_BOT_NAME and f">{FEISHU_BOT_NAME}<" in raw_message and "<at" in raw_message:
        return True
    return False


async def should_handle_feishu_message(message: Dict) -> bool:
    chat_type = (message.get("chat_type") or "").lower()
    if chat_type not in {"group", "topic_group"}:
        return True

    bot_open_id = await get_feishu_bot_open_id()
    return feishu_message_mentions_bot(message, bot_open_id)


async def reply_feishu_message(message_id: Optional[str], text: str):
    if not message_id:
        return

    try:
        token = await get_feishu_tenant_access_token()
        if not token:
            logger.warning("Feishu credentials are not configured; skipped message reply.")
            return

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"https://open.feishu.cn/open-apis/im/v1/messages/{message_id}/reply",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "msg_type": "text",
                    "content": json.dumps({"text": text}, ensure_ascii=False),
                },
            )
            if response.status_code >= 400:
                logger.warning(
                    "Feishu reply failed: status=%s body=%s",
                    response.status_code,
                    response.text[:1000],
                )
    except Exception as e:
        logger.warning(f"Failed to reply to Feishu message: {e}")


def extract_feishu_text(message: Dict) -> str:
    content = message.get("content") or "{}"
    try:
        content_data = json.loads(content)
    except json.JSONDecodeError:
        return content
    return content_data.get("text", "")


def get_feishu_tenant_access_token_sync() -> Optional[str]:
    if not FEISHU_APP_ID or not FEISHU_APP_SECRET:
        return None

    with httpx.Client(timeout=15.0) as client:
        response = client.post(
            "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
            json={"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET},
        )
        response.raise_for_status()
        return response.json().get("tenant_access_token")


def reply_feishu_message_sync(message_id: Optional[str], text: str):
    if not message_id:
        return

    try:
        token = get_feishu_tenant_access_token_sync()
        if not token:
            logger.warning("Feishu credentials are not configured; skipped message reply.")
            return

        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                f"https://open.feishu.cn/open-apis/im/v1/messages/{message_id}/reply",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "msg_type": "text",
                    "content": json.dumps({"text": text}, ensure_ascii=False),
                },
            )
            if response.status_code >= 400:
                logger.warning(
                    "Feishu sync reply failed: status=%s body=%s",
                    response.status_code,
                    response.text[:1000],
                )
    except Exception as e:
        logger.warning(f"Failed to sync reply to Feishu message: {e}")


def read_text_file(path: str) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        logger.warning(f"Failed to read text file {path}: {e}")
        return ""


def zh_label(label: str) -> str:
    label = str(label or "").strip()
    return FINANCIAL_LABEL_ZH.get(label, label)


def zh_value(value) -> str:
    text = str(value)
    for source, target in TEXT_ZH_REPLACEMENTS.items():
        text = text.replace(source, target)
    return text


def compact_financial_value(value: str) -> str:
    text = zh_value(value)
    try:
        number = float(str(text).replace(",", ""))
    except (TypeError, ValueError):
        return text

    if abs(number) >= 1_000_000_000:
        return f"{number / 1_000_000_000:.2f}B"
    if abs(number) >= 1_000_000:
        return f"{number / 1_000_000:.2f}M"
    if abs(number) >= 100:
        return f"{number:.2f}"
    return f"{number:.2f}".rstrip("0").rstrip(".")


def read_metric_summary(csv_path: str, limit: int = 12) -> List[str]:
    if not os.path.exists(csv_path):
        return []

    rows = []
    try:
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                metric = zh_label(row.get("metrics"))
                if not metric:
                    continue
                values = [
                    f"{zh_label(key)} {compact_financial_value(value)}"
                    for key, value in row.items()
                    if key != "metrics" and value not in (None, "")
                ]
                rows.append(f"{metric}：" + "；".join(values[:7]))
                if len(rows) >= limit:
                    break
    except Exception as e:
        logger.warning(f"Failed to read metric summary {csv_path}: {e}")
    return rows


def read_csv_summary(csv_path: str, title_field: str, limit: int = 8) -> List[str]:
    if not os.path.exists(csv_path):
        return []

    rows = []
    try:
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                title = row.get(title_field) or row.get("ticker") or row.get("Ticker") or row.get("metrics")
                if not title:
                    continue
                values = [
                    f"{zh_label(key)}: {zh_value(value)}"
                    for key, value in row.items()
                    if key != title_field and value not in (None, "")
                ]
                rows.append(f"{zh_value(title)} | " + " | ".join(values[:5]))
                if len(rows) >= limit:
                    break
    except Exception as e:
        logger.warning(f"Failed to read CSV summary {csv_path}: {e}")
    return rows


def read_json_summary(json_path: str, limit: int = 8) -> List[str]:
    if not os.path.exists(json_path):
        return []

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.warning(f"Failed to read JSON summary {json_path}: {e}")
        return []

    rows = []

    def flatten(prefix: str, value):
        if len(rows) >= limit:
            return
        if isinstance(value, dict):
            simple_values = [
                f"{zh_label(key)}: {zh_value(item)}"
                for key, item in value.items()
                if not isinstance(item, (dict, list)) and item not in (None, "")
            ]
            if simple_values:
                if prefix:
                    rows.append(f"{zh_value(prefix)} | " + " | ".join(simple_values[:5]))
                else:
                    rows.append(" | ".join(simple_values[:5]))
            for key, item in value.items():
                label = zh_label(str(key))
                flatten(f"{prefix}.{label}" if prefix else label, item)
        elif isinstance(value, list):
            for index, item in enumerate(value[:limit]):
                flatten(f"{prefix}[{index + 1}]", item)
        elif value not in (None, ""):
            rows.append(f"{zh_value(prefix)}: {zh_value(value)}")

    flatten("", data)
    return rows[:limit]


def feishu_text_block(content: str, bold: bool = False) -> Dict:
    return {
        "block_type": 2,
        "text": {
            "elements": [
                {
                    "text_run": {
                        "content": content[:1800],
                        "text_element_style": {"bold": bold},
                    }
                }
            ],
            "style": {},
        },
    }


def split_paragraphs(text: str, max_len: int = 1200) -> List[str]:
    text = re.sub(r"\n{3,}", "\n\n", text or "").strip()
    if not text:
        return []

    paragraphs = []
    for raw in text.split("\n\n"):
        raw = raw.strip()
        if not raw:
            continue
        while len(raw) > max_len:
            paragraphs.append(raw[:max_len])
            raw = raw[max_len:].strip()
        if raw:
            paragraphs.append(raw)
    return paragraphs


def add_doc_section(blocks: List[Dict], title: str, body: str, max_paragraphs: int = 12):
    if not (body or "").strip():
        return

    blocks.append(feishu_text_block(title, bold=True))
    paragraphs = split_paragraphs(body)
    for paragraph in paragraphs[:max_paragraphs]:
        blocks.append(feishu_text_block(paragraph))


def build_chinese_report_blocks(req: AnalysisRequest, analysis_output_dir: str, report_output_dir: str) -> List[Dict]:
    metric_rows = read_metric_summary(os.path.join(analysis_output_dir, "financial_metrics_and_forecasts.csv"))
    peer_ebitda_rows = read_csv_summary(os.path.join(analysis_output_dir, "peer_ebitda_comparison.csv"), "ticker")
    peer_ev_rows = read_csv_summary(os.path.join(analysis_output_dir, "peer_ev_ebitda_comparison.csv"), "ticker")

    metric_body = "\n".join(f"- {row}" for row in metric_rows[:10])
    peer_body = "\n".join(f"- {row}" for row in (peer_ebitda_rows + peer_ev_rows)[:8])

    fallback_takeaways = ""
    if metric_rows:
        fallback_takeaways = (
            f"{req.company_name}（{req.ticker}）的本次报告已完成基础财务抓取、预测测算"
            "和结构化投研整理。以下结论基于 FMP 财务数据自动生成，建议结合公司公告、"
            "最新财报电话会和市场价格进一步复核。\n"
            + "\n".join(f"- {row}" for row in metric_rows[:5])
        )
    investment_focus = (
        "1. 增长质量：重点查看营收增长、EBITDA 与 EBITDA 利润率是否同步改善。\n"
        "2. 估值位置：结合 PE、PS、EV/EBITDA 和同行表判断当前价格是否透支预期。\n"
        "3. 风险因素：关注需求周期、毛利率波动、费用率变化和监管/竞争压力。\n"
        "4. 完整图表：飞书文档保留中文正文与关键数据，专业 HTML 研报提供更完整的图表、表格和分节排版。"
    )
    data_coverage = (
        "飞书文档呈现完整中文正文和关键数据摘要；专业 HTML 研报保留图表、表格、估值、"
        "同行比较、敏感性分析、催化剂和风险等完整模块。若某个模块的数据源未返回，"
        "文档会明确标注数据覆盖状态，而不是静默删除分析框架。"
    )

    html_files = []
    if os.path.exists(report_output_dir):
        html_files = [f for f in os.listdir(report_output_dir) if f.endswith(".html")]
    professional_files = [f for f in html_files if "Professional_Equity_Report" in f]
    selected_html = (professional_files or html_files or [None])[0]
    report_link = public_url(f"/output/{req.ticker}/report/{selected_html}") if selected_html else ""
    takeaways = read_text_file(os.path.join(analysis_output_dir, "major_takeaways.txt")) or fallback_takeaways
    overview = read_text_file(os.path.join(analysis_output_dir, "investment_overview.txt")) or investment_focus
    valuation = read_text_file(os.path.join(analysis_output_dir, "valuation_overview.txt"))

    intro_parts = [
        f"本页是 {req.company_name}（{req.ticker}）FinRobot HTML 股票研究报告的飞书知识库索引页。",
        "主报告只保留一份专业 HTML，飞书不再生成缩水版正文；请打开 HTML 查看完整图表、表格、估值、同行比较、风险和催化剂模块。",
    ]
    if report_link:
        intro_parts.append(f"HTML 研报链接：{report_link}")

    sections = {
        "HTML 研报入口": report_link or "HTML 研报文件未找到，请查看任务状态和 Render 输出目录。",
        "研报介绍": "\n".join(intro_parts),
        "核心结论摘录": takeaways,
        "投资观点摘录": overview,
        "估值摘录": valuation,
        "关键财务指标摘录": metric_body,
        "同行比较摘录": peer_body,
        "沉淀方式": (
            "飞书：本索引页已创建在指定文档库下面，作为知识库入口。\n"
            "Obsidian：系统会把索引 Markdown 和 HTML 副本同步到配置的 GitHub 知识库仓库；"
            "本机 Obsidian 通过 Git 同步后即可检索。"
        ),
        "数据覆盖说明": data_coverage,
    }

    blocks = [
        feishu_text_block(f"{req.company_name}（{req.ticker}）HTML 股票研究报告索引", bold=True),
        feishu_text_block(
            "本页用于飞书知识库归档和检索；完整研报以 HTML 链接为准。内容仅供投研参考，不构成投资建议。"
        ),
    ]
    for title, body in sections.items():
        add_doc_section(blocks, title, body, max_paragraphs=4)

    if len(blocks) <= 2:
        add_doc_section(
            blocks,
            "生成状态",
            "本次任务完成了文档创建，但未读取到可用的财务 CSV、同行比较或分析文本。请检查 FMP 权限、股票代码和 Render 任务日志后重试。",
        )
    return blocks


def create_feishu_document(title: str, blocks: List[Dict], chat_id: Optional[str] = None) -> Dict:
    token = get_feishu_tenant_access_token_sync()
    if not token:
        raise RuntimeError("Feishu credentials are not configured.")

    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=30.0) as client:
        node_token = None
        document_url = None

        if FEISHU_WIKI_PARENT_TOKEN:
            space_id = FEISHU_WIKI_SPACE_ID
            if not space_id:
                parent_response = client.get(
                    "https://open.feishu.cn/open-apis/wiki/v2/spaces/get_node",
                    headers=headers,
                    params={"token": FEISHU_WIKI_PARENT_TOKEN, "obj_type": "wiki"},
                )
                parent_response.raise_for_status()
                parent_data = parent_response.json()
                if parent_data.get("code") != 0:
                    raise RuntimeError(f"Feishu wiki parent lookup failed: {parent_data}")
                space_id = parent_data["data"]["node"]["space_id"]

            create_response = client.post(
                f"https://open.feishu.cn/open-apis/wiki/v2/spaces/{space_id}/nodes",
                headers=headers,
                json={
                    "obj_type": "docx",
                    "node_type": "origin",
                    "parent_node_token": FEISHU_WIKI_PARENT_TOKEN,
                    "title": title,
                },
            )
            create_response.raise_for_status()
            create_data = create_response.json()
            if create_data.get("code") != 0:
                raise RuntimeError(f"Feishu wiki document create failed: {create_data}")

            node = create_data["data"]["node"]
            document_id = node["obj_token"]
            node_token = node["node_token"]
            document_url = node.get("url")
        else:
            create_response = client.post(
                "https://open.feishu.cn/open-apis/docx/v1/documents",
                headers=headers,
                json={"title": title},
            )
            create_response.raise_for_status()
            create_data = create_response.json()
            if create_data.get("code") != 0:
                raise RuntimeError(f"Feishu document create failed: {create_data}")

            document_id = create_data["data"]["document"]["document_id"]
            document_url = f"{FEISHU_DOC_BASE_URL.rstrip('/')}/{document_id}"

        for start in range(0, len(blocks), 20):
            chunk = blocks[start:start + 20]
            block_response = client.post(
                f"https://open.feishu.cn/open-apis/docx/v1/documents/{document_id}/blocks/{document_id}/children",
                headers=headers,
                json={"children": chunk},
            )
            block_response.raise_for_status()
            block_data = block_response.json()
            if block_data.get("code") != 0:
                raise RuntimeError(f"Feishu document block create failed: {block_data}")

        if chat_id:
            perm_response = client.post(
                f"https://open.feishu.cn/open-apis/drive/v1/permissions/{document_id}/members",
                params={"type": "docx"},
                headers=headers,
                json={"member_type": "openchat", "member_id": chat_id, "perm": "view"},
            )
            if perm_response.status_code >= 400:
                logger.warning(
                    "Feishu document permission failed: status=%s body=%s",
                    perm_response.status_code,
                    perm_response.text[:1000],
                )

    return {
        "document_id": document_id,
        "node_token": node_token,
        "url": document_url or f"{FEISHU_DOC_BASE_URL.rstrip('/')}/{node_token or document_id}",
    }


def github_repo_parts(repo: str) -> Optional[tuple]:
    clean = re.sub(r"^https://github\.com/", "", str(repo or "").strip(), flags=re.IGNORECASE)
    clean = re.sub(r"\.git$", "", clean)
    parts = [part for part in clean.split("/") if part]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def github_get_file(client: httpx.Client, owner: str, repo: str, path: str) -> Dict:
    encoded_path = "/".join(quote(part, safe="") for part in path.split("/") if part)
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{encoded_path}"
    response = client.get(url, params={"ref": OBSIDIAN_GITHUB_BRANCH})
    if response.status_code == 404:
        return {"sha": "", "content": ""}
    response.raise_for_status()
    data = response.json()
    raw = base64.b64decode((data.get("content") or "").encode("utf-8")).decode("utf-8")
    return {"sha": data.get("sha", ""), "content": raw}


def github_put_file(client: httpx.Client, owner: str, repo: str, path: str, content: str, message: str) -> Dict:
    remote = github_get_file(client, owner, repo, path)
    if remote.get("content") == content:
        return {"path": path, "changed": False, "sha": remote.get("sha", "")}

    encoded_path = "/".join(quote(part, safe="") for part in path.split("/") if part)
    body = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": OBSIDIAN_GITHUB_BRANCH,
    }
    if remote.get("sha"):
        body["sha"] = remote["sha"]

    response = client.put(f"https://api.github.com/repos/{owner}/{repo}/contents/{encoded_path}", json=body)
    response.raise_for_status()
    data = response.json()
    return {"path": path, "changed": True, "sha": data.get("content", {}).get("sha", "")}


def github_append_unique(client: httpx.Client, owner: str, repo: str, path: str, block: str, message: str) -> Dict:
    remote = github_get_file(client, owner, repo, path)
    current = str(remote.get("content") or "").rstrip()
    clean_block = str(block or "").strip()
    if not clean_block:
        return {"path": path, "changed": False, "sha": remote.get("sha", "")}
    if clean_block in current:
        return {"path": path, "changed": False, "sha": remote.get("sha", "")}
    next_content = f"{current}\n\n{clean_block}\n" if current else f"{clean_block}\n"
    return github_put_file(client, owner, repo, path, next_content, message)


def read_report_html_for_sync(html_path: str, req: AnalysisRequest) -> str:
    if not html_path or not os.path.exists(html_path):
        return ""
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
    except Exception as e:
        logger.warning(f"Failed to read HTML for Obsidian sync: {e}")
        return ""

    base = public_url(f"/output/{req.ticker}/report/")
    return re.sub(
        r'(<img[^>]+src=["\'])(?!https?://|data:|/)([^"\']+)(["\'])',
        lambda m: f"{m.group(1)}{base}{m.group(2)}{m.group(3)}",
        html,
        flags=re.IGNORECASE,
    )


def build_finrobot_obsidian_markdown(
    req: AnalysisRequest,
    html_url: str,
    feishu_doc_url: str,
    task_id: str,
    analysis_output_dir: str,
) -> str:
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    takeaways = read_text_file(os.path.join(analysis_output_dir, "major_takeaways.txt"))
    overview = read_text_file(os.path.join(analysis_output_dir, "investment_overview.txt"))
    valuation = read_text_file(os.path.join(analysis_output_dir, "valuation_overview.txt"))
    metrics = read_metric_summary(os.path.join(analysis_output_dir, "financial_metrics_and_forecasts.csv"), limit=8)
    peers = ", ".join(req.peers) if req.peers else "未指定"

    metric_lines = "\n".join(f"- {row}" for row in metrics) if metrics else "- 本次未读取到关键财务指标。"
    body_sections = [
        "---",
        f"source_type: finrobot_equity_report",
        f"ticker: {req.ticker}",
        f"company: {req.company_name}",
        f"peers: {peers}",
        f"generated_at: {generated_at}",
        f"html_url: {html_url}",
        f"feishu_doc_url: {feishu_doc_url}",
        f"task_id: {task_id}",
        "tags:",
        "  - finrobot",
        "  - equity-research",
        f"  - ticker/{req.ticker.lower()}",
        "---",
        "",
        f"# {req.company_name}（{req.ticker}）HTML 股票研究报告",
        "",
        f"- HTML 研报：{html_url or '未生成'}",
        f"- 飞书知识库索引：{feishu_doc_url or '未创建'}",
        f"- 同行公司：{peers}",
        f"- 任务 ID：{task_id}",
        "",
        "## 研报定位",
        "本笔记是 FinRobot 自动生成的 HTML 研报索引。主阅读入口是 HTML，Obsidian 用于长期检索、主题链接和版本沉淀。",
        "",
        "## 核心结论摘录",
        takeaways or "本次未生成核心结论文本，请打开 HTML 查看结构化数据和图表。",
        "",
        "## 投资观点摘录",
        overview or "本次未生成投资观点文本。",
        "",
        "## 估值摘录",
        valuation or "本次未生成估值文本。",
        "",
        "## 关键财务指标",
        metric_lines,
        "",
        "## 后续跟踪",
        "- 复核最新财报、电话会和公司公告。",
        "- 对照同行估值、盈利质量和风险催化剂变化。",
        "- 若 HTML 中有模块显示数据源未返回，优先检查 FMP 权限和对应数据覆盖。",
    ]
    return "\n".join(body_sections).strip() + "\n"


def sync_finrobot_report_to_obsidian(
    req: AnalysisRequest,
    html_url: str,
    feishu_doc_url: str,
    task_id: str,
    report_output_dir: str,
    analysis_output_dir: str,
    html_filename: str,
) -> Dict:
    if not OBSIDIAN_SYNC_ENABLED:
        return {"synced": False, "reason": "disabled"}
    if not OBSIDIAN_GITHUB_TOKEN:
        return {"synced": False, "reason": "missing_obsidian_github_token"}
    repo_parts = github_repo_parts(OBSIDIAN_GITHUB_REPO)
    if not repo_parts:
        return {"synced": False, "reason": "invalid_obsidian_github_repo"}

    owner, repo = repo_parts
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    ticker_slug = slugify_report_part(req.ticker.lower(), "ticker")
    company_slug = slugify_report_part(req.company_name.lower(), ticker_slug)
    folder = f"{OBSIDIAN_FINROBOT_FOLDER}/{ticker_slug}"
    note_path = f"{folder}/{timestamp}-{company_slug}-{ticker_slug}-equity-report.md"
    html_sync_path = f"{folder}/{timestamp}-{ticker_slug}-professional-equity-report.html"
    index_path = f"{OBSIDIAN_FINROBOT_FOLDER}/index.md"

    markdown = build_finrobot_obsidian_markdown(req, html_url, feishu_doc_url, task_id, analysis_output_dir)
    html_path = os.path.join(report_output_dir, html_filename) if html_filename else ""
    html_content = read_report_html_for_sync(html_path, req)
    index_block = (
        f"- {datetime.utcnow().strftime('%Y-%m-%d')} "
        f"[[{note_path.replace('.md', '')}|{req.company_name}（{req.ticker}）]] "
        f"- [HTML]({html_url})"
        f"{f' - [飞书]({feishu_doc_url})' if feishu_doc_url else ''}"
    )

    headers = {
        "Authorization": f"Bearer {OBSIDIAN_GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    with httpx.Client(timeout=OBSIDIAN_GITHUB_TIMEOUT, headers=headers) as client:
        note_result = github_put_file(
            client,
            owner,
            repo,
            note_path,
            markdown,
            f"Add FinRobot report note for {req.ticker}",
        )
        html_result = None
        if html_content:
            html_result = github_put_file(
                client,
                owner,
                repo,
                html_sync_path,
                html_content,
                f"Add FinRobot HTML report for {req.ticker}",
            )
        index_result = github_append_unique(
            client,
            owner,
            repo,
            index_path,
            index_block,
            f"Index FinRobot report for {req.ticker}",
        )

    return {
        "synced": True,
        "note_path": note_result["path"],
        "html_path": html_result["path"] if html_result else "",
        "index_path": index_result["path"],
        "repo": OBSIDIAN_GITHUB_REPO,
        "branch": OBSIDIAN_GITHUB_BRANCH,
    }


def build_feishu_event_key(payload: Dict, message: Dict, text: str) -> str:
    """Build a stable idempotency key for a Feishu message event."""
    header = payload.get("header", {}) if isinstance(payload, dict) else {}
    event_id = header.get("event_id")
    message_id = message.get("message_id")
    chat_id = message.get("chat_id")
    if message_id:
        return f"message:{message_id}"
    if event_id:
        return f"event:{event_id}"
    text_hash = hashlib.sha256((text or "").strip().encode("utf-8")).hexdigest()
    return f"fallback:{chat_id or 'unknown'}:{text_hash}"


def reserve_feishu_task(payload: Dict, message: Dict, text: str, req: AnalysisRequest) -> tuple[str, bool]:
    """Reserve a task id for a Feishu event. Duplicate events reuse the first task."""
    event_key = build_feishu_event_key(payload, message, text)
    task_id = str(uuid.uuid4())
    text_hash = hashlib.sha256((text or "").strip().encode("utf-8")).hexdigest()
    db = SessionLocal()
    try:
        record, created = crud.reserve_feishu_event(
            db=db,
            event_key=event_key,
            task_id=task_id,
            message_id=message.get("message_id"),
            chat_id=message.get("chat_id"),
            text_hash=text_hash,
        )
    finally:
        db.close()

    if not created:
        logger.info(
            "Duplicate Feishu event ignored: event_key=%s existing_task_id=%s",
            event_key,
            record.task_id,
        )
        return record.task_id, False

    tasks[task_id] = {
        "status": "pending",
        "logs": [],
        "result": None,
        "user": "feishu",
        "feishu_message_id": message.get("message_id"),
        "feishu_chat_id": message.get("chat_id"),
    }
    write_log_to_file(task_id, "Task created by Feishu bot")
    write_log_to_file(task_id, f"Ticker: {req.ticker}, Company: {req.company_name}")
    return task_id, True


@app.get("/api/ping")
async def ping():
    return Response(content="ok", media_type="text/plain")


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "finrobot-equity",
        "feishu_configured": bool(FEISHU_APP_ID and FEISHU_APP_SECRET),
        "feishu_bot_open_id_configured": bool(_FEISHU_BOT_OPEN_ID_CACHE),
    }


@app.post("/api/feishu/events")
async def feishu_events(payload: Dict, background_tasks: BackgroundTasks):
    challenge = payload.get("challenge") or payload.get("event", {}).get("challenge")
    if challenge:
        return {"challenge": challenge}

    token = payload.get("token") or payload.get("header", {}).get("token")
    if FEISHU_VERIFICATION_TOKEN and token != FEISHU_VERIFICATION_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid Feishu verification token")

    event = payload.get("event", {})
    message = event.get("message", {})
    if not message:
        return {"success": True, "ignored": "no message event"}

    if not await should_handle_feishu_message(message):
        logger.info(
            "Ignored Feishu group message without %s mention: message_id=%s chat_id=%s",
            FEISHU_BOT_NAME,
            message.get("message_id"),
            message.get("chat_id"),
        )
        return {"success": True, "ignored": "group message without bot mention"}

    message_id = message.get("message_id")
    text = extract_feishu_text(message)
    req = parse_feishu_report_request(text)

    if not req:
        await reply_feishu_message(
            message_id,
            "你可以直接说：帮我生成 PDD 的投研报告，对比 BABA JD SE\n"
            "也可以用指令：/fastreport PDD PDD Holdings Inc | BABA JD SE\n"
            "我会生成专业 HTML 研报，并同步飞书知识库索引和 Obsidian。",
        )
        return {"success": True, "ignored": "unsupported command"}

    chat_id = message.get("chat_id")
    task_id, created = reserve_feishu_task(payload, message, text, req)
    if not created:
        return {"success": True, "duplicate": True, "task_id": task_id}

    background_tasks.add_task(execute_feishu_analysis_pipeline, task_id, req, message_id, chat_id)
    status_link = public_url(f"/api/feishu/status/{task_id}")
    await reply_feishu_message(
        message_id,
        f"已开始生成 {req.company_name}（{req.ticker}）专业 HTML 投研报告，并同步飞书知识库索引。\n"
        f"任务 ID：{task_id}\n状态：{status_link}",
    )
    return {"success": True, "task_id": task_id}


@app.get("/api/feishu/status/{task_id}")
async def get_feishu_task_status(task_id: str):
    if task_id in tasks:
        task = tasks[task_id]
        return {
            "task_id": task_id,
            "status": task.get("status"),
            "result": task.get("result"),
            "log_tail": task.get("logs", [])[-20:],
        }

    file_logs = read_log_from_file(task_id)
    if file_logs:
        return {
            "task_id": task_id,
            "status": "unknown",
            "result": None,
            "log_tail": file_logs[-20:],
            "message": "Task logs found after service restart.",
        }

    raise HTTPException(status_code=404, detail="Task not found")

def run_process(command, task_id, cwd=None):
    """Run a shell command and capture output to the task logs."""
    logger.info(f"Task {task_id}: Running command: {' '.join(command)}")
    append_task_log(task_id, f"Executing: {' '.join(command)}")  # 修改：使用新函数
    
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=cwd or SRC_ROOT
        )
        
        for line in process.stdout:
            append_task_log(task_id, line.strip())  # 修改：使用新函数
            
        process.wait()
        
        if process.returncode != 0:
            raise Exception(f"Command failed with return code {process.returncode}")
            
        return True
    except Exception as e:
        append_task_log(task_id, f"Error: {str(e)}")  # 修改：使用新函数
        tasks[task_id]["status"] = "failed"
        return False

def execute_analysis_pipeline(task_id: str, req: AnalysisRequest):
    tasks[task_id]["status"] = "running"
    append_task_log(task_id, "Starting analysis pipeline...")  # 修改：使用新函数
    
    # Update report status in database
    try:
        db = SessionLocal()
        crud.update_report_request(db, task_id, "running")
        db.close()
    except Exception as e:
        logger.warning(f"Failed to update report status: {e}")
    
    python_exe = sys.executable
    src_dir = os.path.join(SRC_ROOT, "src")  # Now points to core/src
    config_file = os.path.join(CONFIG_DIR, "config.ini")
    
    # Create output directories
    analysis_output_dir = os.path.join(OUTPUT_DIR, req.ticker, "analysis")
    report_output_dir = os.path.join(OUTPUT_DIR, req.ticker, "report")
    os.makedirs(analysis_output_dir, exist_ok=True)
    os.makedirs(report_output_dir, exist_ok=True)
    
    # Step 1: Generate Financial Analysis
    cmd_analysis = [
        python_exe,
        os.path.join(src_dir, "generate_financial_analysis.py"),
        "--company-ticker", req.ticker,
        "--company-name", req.company_name,
        "--years-limit", str(req.years_limit),
        "--revenue-growth-2025", str(req.revenue_growth_2025),
        "--revenue-growth-2026", str(req.revenue_growth_2026),
        "--revenue-growth-2027", str(req.revenue_growth_2027),
        "--margin-improvement", str(req.margin_improvement),
        "--output-dir", analysis_output_dir
    ]
    
    if req.peers:
        cmd_analysis.append("--peer-tickers")
        cmd_analysis.extend(req.peers)
        
    if req.generate_text:
        cmd_analysis.append("--generate-text-sections")
    
    # 新增增强功能选项
    if req.enable_sensitivity_analysis:
        cmd_analysis.append("--enable-sensitivity-analysis")
    if req.enable_catalyst_analysis:
        cmd_analysis.append("--enable-catalyst-analysis")
    if req.enable_enhanced_news:
        cmd_analysis.append("--enable-enhanced-news")
        
    cmd_analysis.extend(["--config-file", config_file])

    if not run_process(cmd_analysis, task_id, cwd=SRC_ROOT):
        # Update report status to failed
        try:
            db = SessionLocal()
            crud.update_report_request(db, task_id, "failed", "Financial analysis failed")
            db.close()
        except Exception as e:
            logger.warning(f"Failed to update report status: {e}")
        return

    analysis_csv_path = os.path.join(analysis_output_dir, "financial_metrics_and_forecasts.csv")
    if not os.path.exists(analysis_csv_path) or os.path.getsize(analysis_csv_path) == 0:
        error_message = (
            "Financial analysis did not produce financial_metrics_and_forecasts.csv. "
            "Check FMP/Finnhub/yfinance access and upstream data logs."
        )
        append_task_log(task_id, f"Error: {error_message}")
        tasks[task_id]["status"] = "failed"
        try:
            db = SessionLocal()
            crud.update_report_request(db, task_id, "failed", error_message)
            db.close()
        except Exception as e:
            logger.warning(f"Failed to update report status: {e}")
        return

    if not req.generate_html_report:
        tasks[task_id]["status"] = "completed"
        append_task_log(task_id, "Analysis completed successfully; skipped HTML/PDF report generation.")
        try:
            db = SessionLocal()
            crud.update_report_request(db, task_id, "completed")
            db.close()
        except Exception as e:
            logger.warning(f"Failed to update report status: {e}")
        tasks[task_id]["result"] = {
            "analysis_dir": analysis_output_dir,
            "report_dir": report_output_dir,
            "ticker": req.ticker,
            "html": [],
            "pdf": [],
        }
        return

    # Step 2: Create Equity Report
    base_output_dir = analysis_output_dir
    
    cmd_report = [
        python_exe,
        os.path.join(src_dir, "create_equity_report.py"),
        "--company-ticker", req.ticker,
        "--company-name", req.company_name,
        "--analysis-csv", os.path.join(base_output_dir, "financial_metrics_and_forecasts.csv"),
        "--ratios-csv", os.path.join(base_output_dir, "ratios_raw_data.csv"),
        "--tagline-file", os.path.join(base_output_dir, "tagline.txt"),
        "--company-overview-file", os.path.join(base_output_dir, "company_overview.txt"),
        "--investment-overview-file", os.path.join(base_output_dir, "investment_overview.txt"),
        "--valuation-overview-file", os.path.join(base_output_dir, "valuation_overview.txt"),
        "--risks-file", os.path.join(base_output_dir, "risks.txt"),
        "--competitor-analysis-file", os.path.join(base_output_dir, "competitor_analysis.txt"),
        "--major-takeaways-file", os.path.join(base_output_dir, "major_takeaways.txt"),
        "--news-summary-file", os.path.join(base_output_dir, "news_summary.txt"),
        "--output-dir", report_output_dir,
        "--config-file", config_file,
    ]

    if req.enable_report_text_regeneration:
        cmd_report.append("--enable-text-regeneration")
    
    # 新增增强功能选项
    if req.enable_enhanced_charts:
        cmd_report.append("--enable-enhanced-charts")
    if req.enable_valuation_analysis:
        cmd_report.append("--enable-valuation-analysis")
    
    # 添加增强分析文件路径
    if req.enable_sensitivity_analysis:
        sensitivity_file = os.path.join(base_output_dir, "sensitivity_analysis.json")
        if os.path.exists(sensitivity_file):
            cmd_report.extend(["--sensitivity-analysis-file", sensitivity_file])
    
    if req.enable_catalyst_analysis:
        catalyst_file = os.path.join(base_output_dir, "catalyst_analysis.json")
        if os.path.exists(catalyst_file):
            cmd_report.extend(["--catalyst-analysis-file", catalyst_file])
    
    if req.enable_enhanced_news:
        enhanced_news_file = os.path.join(base_output_dir, "enhanced_news.json")
        if os.path.exists(enhanced_news_file):
            cmd_report.extend(["--enhanced-news-file", enhanced_news_file])

    retail_sentiment_file = os.path.join(base_output_dir, "retail_sentiment.json")
    if os.path.exists(retail_sentiment_file):
        cmd_report.extend(["--retail-sentiment-file", retail_sentiment_file])
    
    if req.peers:
        cmd_report.extend([
            "--peer-ebitda-csv", os.path.join(base_output_dir, "peer_ebitda_comparison.csv"),
            "--peer-ev-ebitda-csv", os.path.join(base_output_dir, "peer_ev_ebitda_comparison.csv")
        ])

    if not run_process(cmd_report, task_id, cwd=SRC_ROOT):
        # Update report status to failed
        try:
            db = SessionLocal()
            crud.update_report_request(db, task_id, "failed", "Report creation failed")
            db.close()
        except Exception as e:
            logger.warning(f"Failed to update report status: {e}")
        return

    # Step 3: Generate PDF Report
    if req.generate_pdf:
        append_task_log(task_id, "Generating PDF report...")  # 修改：使用新函数
        cmd_pdf = [
            python_exe,
            os.path.join(src_dir, "generate_pdf_report.py"),
            "--company-ticker", req.ticker,
            "--company-name", req.company_name,
            "--analysis-dir", base_output_dir,
            "--output-dir", report_output_dir,
            "--config-file", config_file
        ]
        
        if not run_process(cmd_pdf, task_id, cwd=SRC_ROOT):
            append_task_log(task_id, "Warning: PDF generation failed, but HTML reports are available.")  # 修改：使用新函数

    tasks[task_id]["status"] = "completed"
    append_task_log(task_id, "Pipeline completed successfully!")  # 修改：使用新函数
    
    # Update report status in database
    try:
        db = SessionLocal()
        crud.update_report_request(db, task_id, "completed")
        db.close()
    except Exception as e:
        logger.warning(f"Failed to update report status: {e}")
    
    # Get report files
    report_files = []
    if os.path.exists(report_output_dir):
        report_files = [f for f in os.listdir(report_output_dir) if f.endswith((".html", ".pdf"))]
    
    # Separate HTML and PDF files — only Professional reports
    html_files = [f for f in report_files if f.endswith('.html')]
    pdf_files = [f for f in report_files if f.endswith('.pdf')]

    # Only Professional HTML; fallback to others only if no Professional exists
    prof_htmls = [f for f in html_files if 'Professional' in f]
    sorted_htmls = prof_htmls if prof_htmls else html_files

    # Only Professional/Equity Report PDFs (exclude chart PDFs like *_ebitda_margin.pdf)
    prof_pdfs = [f for f in pdf_files if 'Professional_Equity_Report' in f]
    if not prof_pdfs:
        prof_pdfs = [f for f in pdf_files if 'Equity_Report' in f]
    sorted_pdfs = prof_pdfs
    
    tasks[task_id]["result"] = {
        "report_dir": report_output_dir,
        "ticker": req.ticker,
        "html": sorted_htmls,
        "pdf": sorted_pdfs
    }


def execute_feishu_analysis_pipeline(
    task_id: str,
    req: AnalysisRequest,
    message_id: Optional[str] = None,
    chat_id: Optional[str] = None,
):
    execute_analysis_pipeline(task_id, req)

    task = tasks.get(task_id, {})
    if task.get("status") != "completed":
        reply_feishu_message_sync(
            message_id,
            f"{req.company_name}（{req.ticker}）投研文档生成失败。\n"
            f"任务 ID：{task_id}\n"
            f"请查看状态：{public_url(f'/api/feishu/status/{task_id}')}",
        )
        return

    try:
        analysis_output_dir = os.path.join(OUTPUT_DIR, req.ticker, "analysis")
        report_output_dir = os.path.join(OUTPUT_DIR, req.ticker, "report")
        html_files = task.get("result", {}).get("html") or []
        html_filename = html_files[0] if html_files else ""
        html_url = public_url(f"/output/{req.ticker}/report/{html_filename}") if html_filename else ""

        title = f"{req.company_name}（{req.ticker}）HTML 研报索引"
        blocks = build_chinese_report_blocks(req, analysis_output_dir, report_output_dir)
        doc = create_feishu_document(title, blocks, chat_id=chat_id)

        obsidian_sync = sync_finrobot_report_to_obsidian(
            req=req,
            html_url=html_url,
            feishu_doc_url=doc.get("url", ""),
            task_id=task_id,
            report_output_dir=report_output_dir,
            analysis_output_dir=analysis_output_dir,
            html_filename=html_filename,
        )

        task.setdefault("result", {})
        task["result"]["feishu_doc"] = doc
        task["result"]["obsidian_sync"] = obsidian_sync
        append_task_log(task_id, f"Created Feishu HTML index document: {doc['url']}")
        if obsidian_sync.get("synced"):
            append_task_log(task_id, f"Synced Obsidian note: {obsidian_sync.get('note_path')}")
            if obsidian_sync.get("html_path"):
                append_task_log(task_id, f"Synced Obsidian HTML copy: {obsidian_sync.get('html_path')}")
        else:
            append_task_log(task_id, f"Obsidian sync skipped: {obsidian_sync.get('reason')}")

        obsidian_line = (
            f"Obsidian：已同步 {obsidian_sync.get('note_path')}"
            if obsidian_sync.get("synced")
            else f"Obsidian：未同步（{obsidian_sync.get('reason', 'unknown')}）"
        )
        reply_text = (
            f"{req.company_name}（{req.ticker}）HTML 投研报告已生成：\n"
            f"专业 HTML 研报：{html_url or '未找到'}\n"
            f"飞书知识库索引：{doc['url']}\n"
            f"{obsidian_line}\n"
        )
        reply_text += f"文档 ID：{doc['document_id']}"
        reply_feishu_message_sync(
            message_id,
            reply_text,
        )
    except Exception as e:
        logger.warning(f"Failed to create Feishu document: {e}")
        append_task_log(task_id, f"Failed to create Feishu document: {e}")
        reply_feishu_message_sync(
            message_id,
            f"{req.company_name}（{req.ticker}）报告已生成，但创建飞书文档失败：{e}\n"
            f"状态：{public_url(f'/api/feishu/status/{task_id}')}",
        )

@app.post("/api/run")
async def run_analysis(req: AnalysisRequest, request: Request, background_tasks: BackgroundTasks):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    task_id = str(uuid.uuid4())
    tasks[task_id] = {"status": "pending", "logs": [], "result": None, "user": user["email"]}
    
    # 初始化日志文件
    write_log_to_file(task_id, f"Task created by user: {user['email']}")
    write_log_to_file(task_id, f"Ticker: {req.ticker}, Company: {req.company_name}")
    
    # Record report request in database
    try:
        db = SessionLocal()
        crud.create_report_request(
            db=db,
            user_id=user["id"],
            task_id=task_id,
            ticker=req.ticker,
            company_name=req.company_name,
            peers=",".join(req.peers) if req.peers else None,
            generate_text=req.generate_text,
            generate_pdf=req.generate_pdf,
            enable_sensitivity=req.enable_sensitivity_analysis,
            enable_catalyst=req.enable_catalyst_analysis,
            enable_enhanced_news=req.enable_enhanced_news
        )
        db.close()
    except Exception as e:
        logger.warning(f"Failed to record report request: {e}")
    
    background_tasks.add_task(execute_analysis_pipeline, task_id, req)
    return {"task_id": task_id}

@app.get("/api/status/{task_id}")
async def get_status(task_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if task_id not in tasks:
        # 尝试从文件读取日志（用于服务器重启后的恢复）
        file_logs = read_log_from_file(task_id)
        if file_logs:
            return {
                "status": "unknown",
                "logs": file_logs,
                "result": None,
                "message": "Task found in log files (server may have restarted)"
            }
        return JSONResponse(status_code=404, content={"message": "Task not found"})
    return tasks[task_id]

# ============== 新增：日志文件读取API ==============

@app.get("/api/logs/{task_id}")
async def get_task_logs(task_id: str, request: Request):
    """获取任务的持久化日志"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    log_path = get_log_file_path(task_id)
    if not os.path.exists(log_path):
        raise HTTPException(status_code=404, detail="Log file not found")
    
    logs = read_log_from_file(task_id)
    return {
        "task_id": task_id,
        "log_file": log_path,
        "logs": logs,
        "line_count": len(logs)
    }

@app.get("/api/logs/{task_id}/download")
async def download_task_logs(task_id: str, request: Request):
    """下载任务日志文件"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    log_path = get_log_file_path(task_id)
    if not os.path.exists(log_path):
        raise HTTPException(status_code=404, detail="Log file not found")
    
    return FileResponse(
        path=log_path,
        filename=f"task_{task_id}.log",
        media_type="text/plain"
    )

@app.get("/api/logs")
async def list_all_logs(request: Request):
    """列出所有日志文件"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # 只有管理员可以查看所有日志
    # Admin emails can be configured via FINROBOT_ADMIN_EMAILS env var (comma-separated)
    admin_emails = os.getenv("FINROBOT_ADMIN_EMAILS", "admin@finrobot.com").split(",")
    admin_emails = [e.strip() for e in admin_emails]
    if user.get("email") not in admin_emails:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    log_files = []
    if os.path.exists(LOGS_DIR):
        for filename in os.listdir(LOGS_DIR):
            if filename.endswith(".log"):
                file_path = os.path.join(LOGS_DIR, filename)
                stat = os.stat(file_path)
                log_files.append({
                    "filename": filename,
                    "task_id": filename.replace("task_", "").replace(".log", ""),
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
    
    # 按修改时间倒序排列
    log_files.sort(key=lambda x: x["modified_at"], reverse=True)
    
    return {
        "logs_dir": LOGS_DIR,
        "total_files": len(log_files),
        "files": log_files
    }

@app.get("/api/history")
async def get_history(request: Request):
    """返回当前用户的历史报告列表，供前端刷新后恢复。"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        db = SessionLocal()
        reports = crud.get_user_reports(db, user["id"], limit=50)
        result = []
        seen_tickers = set()
        for r in reports:
            # 同一 ticker 只显示一条（最新的），因为输出文件是覆盖的
            if r.ticker in seen_tickers:
                continue
            seen_tickers.add(r.ticker)
            # 检查报告文件是否存在
            report_dir = os.path.join(OUTPUT_DIR, r.ticker, "report")
            html_files = []
            pdf_files = []
            if os.path.exists(report_dir):
                all_files = os.listdir(report_dir)
                # 只要 Professional 报告，排除 Combined
                prof_html = [f for f in all_files if f.endswith('.html') and 'Professional' in f]
                other_html = [f for f in all_files if f.endswith('.html') and 'Professional' not in f] if not prof_html else []
                html_files = prof_html + other_html
                # 只要 Professional PDF 报告，排除图表 PDF
                prof_pdf = [f for f in all_files if f.endswith('.pdf') and 'Professional_Equity_Report' in f]
                other_pdf = [f for f in all_files if f.endswith('.pdf') and 'Equity_Report' in f and f not in prof_pdf] if not prof_pdf else []
                pdf_files = prof_pdf + other_pdf
            result.append({
                "task_id": r.task_id,
                "ticker": r.ticker,
                "company_name": r.company_name,
                "status": r.status or "completed",
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "html": html_files,
                "pdf": pdf_files,
            })
        db.close()
        return result
    except Exception as e:
        logger.warning(f"Failed to load history: {e}")
        return []


@app.delete("/api/history/{task_id}")
async def delete_history(task_id: str, request: Request):
    """删除指定的历史报告记录（同时删除同一 ticker 的所有记录）"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        db = SessionLocal()
        # 先找到该 task_id 对应的 ticker
        report = db.query(ReportRequest).filter(
            ReportRequest.task_id == task_id,
            ReportRequest.user_id == user["id"]
        ).first()
        if not report:
            db.close()
            raise HTTPException(status_code=404, detail="Report not found")
        ticker = report.ticker
        # 删除该用户该 ticker 的所有记录
        db.query(ReportRequest).filter(
            ReportRequest.ticker == ticker,
            ReportRequest.user_id == user["id"]
        ).delete()
        db.commit()
        db.close()
        # 同时从内存中移除
        if task_id in tasks:
            del tasks[task_id]
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to delete report: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete report")


@app.get("/api/reports/{ticker}")
async def list_reports(ticker: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    report_dir = os.path.join(OUTPUT_DIR, ticker, "report")
    if not os.path.exists(report_dir):
        return {"reports": []}
    
    reports = [f for f in os.listdir(report_dir) if f.endswith((".html", ".pdf"))]
    return {"reports": reports}
