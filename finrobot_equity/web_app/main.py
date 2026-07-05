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
import httpx
from datetime import datetime, timedelta
from typing import List, Optional, Dict
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

def write_log_to_file(task_id: str, message: str):
    """将日志写入文件"""
    log_path = get_log_file_path(task_id)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logger.warning(f"Failed to write log to file: {e}")

def read_log_from_file(task_id: str) -> List[str]:
    """从文件读取日志"""
    log_path = get_log_file_path(task_id)
    if not os.path.exists(log_path):
        return []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines()]
    except Exception as e:
        logger.warning(f"Failed to read log from file: {e}")
        return []

def append_task_log(task_id: str, message: str):
    """同时写入内存和文件的日志函数"""
    # 写入内存
    if task_id in tasks:
        tasks[task_id]["logs"].append(message)
    # 写入文件
    write_log_to_file(task_id, message)

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
FEISHU_DOC_BASE_URL = os.getenv("FEISHU_DOC_BASE_URL", "https://feishu.cn/docx")
FEISHU_WIKI_PARENT_TOKEN = os.getenv("FEISHU_WIKI_PARENT_TOKEN", "")
FEISHU_WIKI_SPACE_ID = os.getenv("FEISHU_WIKI_SPACE_ID", "")
PUBLIC_BASE_URL = os.getenv("FINROBOT_PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL", "")

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


def public_url(path: str) -> str:
    if not PUBLIC_BASE_URL:
        return path
    return f"{PUBLIC_BASE_URL.rstrip('/')}/{path.lstrip('/')}"


def parse_feishu_report_request(text: str) -> Optional[AnalysisRequest]:
    clean_text = re.sub(r"<at[^>]*>.*?</at>", "", text or "", flags=re.IGNORECASE).strip()
    lower_text = clean_text.lower()

    has_report_prefix = False
    for prefix in ("/report", "report"):
        if lower_text.startswith(prefix):
            clean_text = clean_text[len(prefix):].strip()
            has_report_prefix = True
            break

    if not has_report_prefix or not clean_text or lower_text in {"/help", "help"}:
        return None

    command_parts = [part.strip() for part in clean_text.split("|", 1)]
    company_part = command_parts[0]
    peer_part = command_parts[1] if len(command_parts) > 1 else ""
    tokens = company_part.split()

    if not tokens:
        return None

    ticker = re.sub(r"[^A-Za-z.\-]", "", tokens[0]).upper()
    if not re.match(r"^[A-Z][A-Z0-9.\-]{0,9}$", ticker):
        return None

    peers = [
        re.sub(r"[^A-Za-z.\-]", "", peer).upper()
        for peer in re.split(r"[\s,]+", peer_part)
        if peer.strip()
    ]
    peers = [peer for peer in peers if re.match(r"^[A-Z][A-Z0-9.\-]{0,9}$", peer)]
    company_name = " ".join(tokens[1:]).strip() or ticker

    return AnalysisRequest(
        ticker=ticker,
        company_name=company_name,
        peers=peers,
        generate_text=True,
        generate_pdf=False,
        generate_html_report=False,
    )


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


def read_metric_summary(csv_path: str, limit: int = 12) -> List[str]:
    if not os.path.exists(csv_path):
        return []

    rows = []
    try:
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                metric = row.get("metrics")
                if not metric:
                    continue
                values = [
                    f"{key}: {value}"
                    for key, value in row.items()
                    if key != "metrics" and value not in (None, "")
                ]
                rows.append(f"{metric} | " + " | ".join(values[:6]))
                if len(rows) >= limit:
                    break
    except Exception as e:
        logger.warning(f"Failed to read metric summary {csv_path}: {e}")
    return rows


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


def add_doc_section(blocks: List[Dict], title: str, body: str):
    blocks.append(feishu_text_block(title, bold=True))
    paragraphs = split_paragraphs(body)
    if not paragraphs:
        paragraphs = ["暂无可用内容。"]
    for paragraph in paragraphs[:6]:
        blocks.append(feishu_text_block(paragraph))


def build_chinese_report_blocks(req: AnalysisRequest, analysis_output_dir: str, report_output_dir: str) -> List[Dict]:
    sections = {
        "核心结论": read_text_file(os.path.join(analysis_output_dir, "major_takeaways.txt")),
        "投资观点": read_text_file(os.path.join(analysis_output_dir, "investment_overview.txt")),
        "公司概览": read_text_file(os.path.join(analysis_output_dir, "company_overview.txt")),
        "财务表现分析": read_text_file(os.path.join(analysis_output_dir, "tagline.txt")),
        "估值分析": read_text_file(os.path.join(analysis_output_dir, "valuation_overview.txt")),
        "同行公司比较": read_text_file(os.path.join(analysis_output_dir, "competitor_analysis.txt")),
        "主要风险": read_text_file(os.path.join(analysis_output_dir, "risks.txt")),
        "新闻与催化因素": read_text_file(os.path.join(analysis_output_dir, "news_summary.txt")),
    }
    metric_rows = read_metric_summary(os.path.join(analysis_output_dir, "financial_metrics_and_forecasts.csv"))
    if metric_rows:
        sections["关键财务指标"] = "\n".join(f"• {row}" for row in metric_rows)

    html_files = []
    if os.path.exists(report_output_dir):
        html_files = [f for f in os.listdir(report_output_dir) if f.endswith(".html")]
    if html_files:
        report_link = public_url(f"/output/{req.ticker}/report/{html_files[0]}")
        sections["在线报告链接"] = report_link

    blocks = [
        feishu_text_block(f"{req.company_name}（{req.ticker}）股票研究报告", bold=True),
        feishu_text_block(
            "本报告由 FinRobot 自动生成，数据来自 FMP，文本由接入模型生成。内容仅供投研参考，不构成投资建议。"
        ),
    ]
    for title, body in sections.items():
        add_doc_section(blocks, title, body)
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


def start_feishu_task(req: AnalysisRequest, message_id: Optional[str] = None, chat_id: Optional[str] = None) -> str:
    task_id = str(uuid.uuid4())
    tasks[task_id] = {
        "status": "pending",
        "logs": [],
        "result": None,
        "user": "feishu",
        "feishu_message_id": message_id,
        "feishu_chat_id": chat_id,
    }
    write_log_to_file(task_id, "Task created by Feishu bot")
    write_log_to_file(task_id, f"Ticker: {req.ticker}, Company: {req.company_name}")
    return task_id


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "finrobot-equity",
        "feishu_configured": bool(FEISHU_APP_ID and FEISHU_APP_SECRET),
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

    message_id = message.get("message_id")
    text = extract_feishu_text(message)
    req = parse_feishu_report_request(text)

    if not req:
        await reply_feishu_message(
            message_id,
            "请发送：/report AAPL Apple Inc | MSFT GOOGL\n"
            "竖线后面是可选的同行股票代码。报告完成后会生成中文飞书文档并回传链接。",
        )
        return {"success": True, "ignored": "unsupported command"}

    chat_id = message.get("chat_id")
    task_id = start_feishu_task(req, message_id=message_id, chat_id=chat_id)
    background_tasks.add_task(execute_feishu_analysis_pipeline, task_id, req, message_id, chat_id)
    status_link = public_url(f"/api/feishu/status/{task_id}")
    await reply_feishu_message(
        message_id,
        f"已开始生成 {req.company_name}（{req.ticker}）中文投研文档。\n"
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
            "Check FMP API access and upstream data logs."
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
        "--output-dir", report_output_dir,
        "--config-file", config_file,
        "--enable-text-regeneration"
    ]
    
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
        title = f"{req.company_name}（{req.ticker}）股票研究报告"
        blocks = build_chinese_report_blocks(req, analysis_output_dir, report_output_dir)
        doc = create_feishu_document(title, blocks, chat_id=chat_id)

        task.setdefault("result", {})
        task["result"]["feishu_doc"] = doc
        append_task_log(task_id, f"Created Feishu document: {doc['url']}")
        reply_feishu_message_sync(
            message_id,
            f"{req.company_name}（{req.ticker}）中文投研文档已生成：\n{doc['url']}\n"
            f"文档 ID：{doc['document_id']}",
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
