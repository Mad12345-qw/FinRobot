#!/usr/bin/env python
# coding: utf-8

import pandas as pd
from typing import Dict, Optional
from openai import OpenAI

from modules.retail_sentiment_client import format_retail_sentiment_for_prompt


def _get_fallback_text(prompt_type: str, company_name: str) -> str:
    """Returns fallback text when agent generation fails."""
    fallbacks = {
        "tagline": f"{company_name} 的财务基本面具备一定韧性，收入增长、盈利能力和资产负债表质量是后续跟踪的核心。公司竞争位置、经营效率和资本回报仍需结合最新财报与同行估值持续验证。",
        "company_overview": f"{company_name} 是所在行业的重要参与者，业务表现取决于终端需求、产品竞争力、成本控制和资本配置效率。后续分析应重点关注收入结构、利润率趋势、现金流质量以及管理层对增长机会的执行能力。",
        "investment_overview": f"{company_name} 的投资判断需要同时考量增长确定性、盈利弹性、估值水平和潜在风险。若公司能够维持收入增长并改善利润率，其长期价值创造能力有望增强；反之，需求放缓或竞争加剧可能压制估值。",
        "valuation_overview": f"{company_name} 的估值应结合历史盈利能力、未来增长预期和同行公司交易倍数进行交叉验证。当前估值是否具备吸引力，取决于市场对增长、利润率和风险溢价的重新定价。",
        "risks": "主要风险包括：1）行业竞争加剧导致市场份额或定价能力下降；2）宏观经济走弱压制需求；3）监管、政策或合规变化影响经营；4）供应链、成本或执行风险；5）估值过高导致股价对业绩波动更敏感。",
        "competitor_analysis": f"{company_name} 的竞争力需要放在同行公司框架中评估，重点比较收入增长、EBITDA 利润率、现金流、估值倍数和市场份额变化。若公司在增长和盈利质量上持续优于同行，则估值溢价更具支撑。",
        "major_takeaways": f"收入增长：{company_name} 的收入趋势是判断基本面动能的首要指标。\n\n毛利率与贡献利润率：利润率变化反映产品结构、成本控制和定价能力。\n\nSG&A 费用率：费用率改善通常意味着运营杠杆释放。\n\nEBITDA 利润率：EBITDA 稳定性体现公司盈利质量和抗周期能力。",
        "news_summary": f"{company_name} 的近期新闻需要从业务进展、行业变化、资本市场反应和潜在风险四个维度判断其投资含义。"
    }
    return fallbacks.get(prompt_type, f"{company_name} 的 {prompt_type.replace('_', ' ')} 分析暂不可用。")


# System prompts for each text section
SYSTEM_PROMPTS = {
    "tagline": "你是资深股票研究分析师。请用简体中文写 3 句话，专业、简洁地概括公司的财务状况、投资亮点和主要观察点。不要使用 Markdown。",
    "company_overview": "你是金融分析师。请用简体中文写公司概览，覆盖商业模式、产品/服务、市场位置和近期经营表现。使用纯文本，不要使用 Markdown。",
    "investment_overview": "你是投资分析师。请用简体中文写投资观点，覆盖近期财务表现、增长驱动、盈利质量和展望。使用纯文本，不要使用 Markdown。",
    "valuation_overview": "你是估值分析师。请用简体中文写估值分析，覆盖估值倍数、同行比较、合理估值判断和关键假设。使用纯文本，不要使用 Markdown。",
    "risks": "你是风险分析师。请用简体中文列出 5 条关键投资风险，每条具体、克制、可执行跟踪。",
    "competitor_analysis": "你是竞争分析师。请用简体中文写同行比较，重点比较增长、利润率、估值倍数和竞争位置。使用纯文本，不要使用 Markdown。",
    "major_takeaways": "你是金融分析师。请用简体中文给出 4 条核心结论，覆盖收入增长、毛利/贡献利润率、SG&A 费用率和 EBITDA 利润率。每条用标题加 1-2 句话。",
    "news_summary": "你是财经新闻分析师。请用简体中文总结近期新闻，突出关键事件、情绪变化和投资含义。使用纯文本，不要使用 Markdown。"
}


def _df_to_string(df: Optional[pd.DataFrame], name: str) -> str:
    """Converts a DataFrame to a markdown string for use in a prompt."""
    if df is None or df.empty:
        return f"{name}:\n[Data not available]\n"
    
    try:
        return f"{name}:\n{df.to_markdown()}\n"
    except Exception as e:
        return f"{name}:\n[Error formatting data: {e}]\n"


def _prepare_user_prompt(data: Dict, prompt_type: str, company_name: str, company_ticker: str) -> str:
    """Prepare user prompt with financial data."""
    financial_metrics = data.get('financial_metrics')
    peer_ebitda = data.get('peer_ebitda')
    peer_ev_ebitda = data.get('peer_ev_ebitda')
    company_news = data.get('company_news')
    retail_sentiment = data.get('retail_sentiment')
    
    prompt = f"公司：{company_name} ({company_ticker})\n\n"
    
    if financial_metrics is not None and not financial_metrics.empty:
        prompt += _df_to_string(financial_metrics, "Financial Metrics")
    
    if peer_ebitda is not None and not peer_ebitda.empty:
        prompt += _df_to_string(peer_ebitda, "Peer EBITDA Comparison")
        
    if peer_ev_ebitda is not None and not peer_ev_ebitda.empty:
        prompt += _df_to_string(peer_ev_ebitda, "Peer EV/EBITDA Comparison")
    
    if prompt_type == "news_summary" and company_news:
        prompt += f"\n## Recent News:\n"
        for i, article in enumerate(company_news[:10], 1):  # Limit to 10 articles
            prompt += f"{i}. {article.get('title', 'N/A')} ({article.get('publishedDate', 'N/A')[:10]})\n"
            prompt += f"   {article.get('text', 'N/A')[:200]}...\n\n"

    if prompt_type == "news_summary" and retail_sentiment:
        prompt += "\n" + format_retail_sentiment_for_prompt(retail_sentiment) + "\n"

    prompt += (
        f"\n请基于以上数据生成 {prompt_type.replace('_', ' ')}。"
        "所有输出必须是简体中文，避免英文段落和英文标题；股票代码、公司英文名和财务指标英文缩写可以保留。"
    )
    return prompt


def generate_text_section(data: Dict, prompt_type: str, api_key: str, company_name: str, company_ticker: str, base_url: str = None, model: str = None) -> str:
    """
    Generates a specific text section for the equity report using OpenAI Chat API.
    
    Args:
        data: Financial data dictionary
        prompt_type: Type of text section to generate
        api_key: OpenAI API key
        company_name: Company name
        company_ticker: Stock ticker
        base_url: Optional API base URL (for proxy services like SiliconFlow)
        model: Optional model name (default: gpt-4o-mini or configured model)
    """
    
    print(f"🤖 Generating '{prompt_type}' text section...")
    
    # Validate API key
    if not api_key:
        print(f"⚠️ Warning: No API key provided. Using fallback text for '{prompt_type}'.")
        return _get_fallback_text(prompt_type, company_name)
    
    # Determine model to use
    default_model = "gpt-4o-mini"
    if model:
        default_model = model
    
    # Create OpenAI client
    try:
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
            print(f"📡 Using API base URL: {base_url}")
        
        client = OpenAI(**client_kwargs)
        print(f"🤖 Using model: {default_model}")
    except Exception as e:
        print(f"⚠️ Warning: Could not create OpenAI client: {e}")
        return _get_fallback_text(prompt_type, company_name)
    
    # Get system prompt
    system_prompt = SYSTEM_PROMPTS.get(prompt_type, f"You are a financial analyst. Provide {prompt_type.replace('_', ' ')} analysis.")
    
    # Prepare user prompt with data
    user_prompt = _prepare_user_prompt(data, prompt_type, company_name, company_ticker)
    
    # Call OpenAI API
    try:
        response = client.chat.completions.create(
            model=default_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        generated_text = response.choices[0].message.content.strip()
        
        if generated_text:
            print(f"✅ Successfully generated '{prompt_type}' ({len(generated_text)} chars)")
            return generated_text
        else:
            print(f"⚠️ Warning: Empty response for '{prompt_type}'")
            return _get_fallback_text(prompt_type, company_name)
            
    except Exception as e:
        print(f"❌ Error generating '{prompt_type}': {e}")
        return _get_fallback_text(prompt_type, company_name)

# Backward compatibility - keep old function signature
def _query_openai(prompt: str, api_key: str) -> str:
    """Legacy function for backward compatibility."""
    return "Text generation now handled by agents."

if __name__ == '__main__':
    print("Testing agent-based text_generator...")
