from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
import httpx
import time

from src.api.auth import verify_api_key
from src.api.db import db_manager
from src.pipeline.detector import PromptInjectionDetector

router = APIRouter()
detector_instance = PromptInjectionDetector()


class AgentGatewayRequest(BaseModel):
    prompt: str = Field(..., description="Inbound prompt or instruction for the AI agent")
    shield_enabled: bool = Field(default=True, description="Whether PromptShield pre-LLM firewall is active")
    agent_endpoint: Optional[str] = Field(default="/api/v1/agent/local", description="Target AI agent endpoint URL or '/api/v1/agent/local'")
    agent_role: Optional[str] = Field(default="email_assistant", description="Agent persona or role")
    agent_model: Optional[str] = Field(default=None, description="Optional LLM model name for OpenAI/Groq/Ollama endpoints")
    api_key: Optional[str] = Field(default=None, description="Optional third-party agent API key")


class AgentGatewayResponse(BaseModel):
    shield_active: bool
    decision: str
    risk_score: int
    attack_category: Optional[str]
    evidence: List[Dict[str, Any]]
    agent_called: bool
    agent_response: str
    tool_execution: str
    breach_occurred: bool
    latency_ms: float


@router.post("/agent/gateway", response_model=AgentGatewayResponse)
async def agent_security_gateway(
    request: AgentGatewayRequest,
    auth_key: str = Depends(verify_api_key),
):
    """
    Production Pre-LLM Security Gateway for Autonomous AI Agents.
    Intercepts untrusted instructions before they reach autonomous agents or LLM tools.
    All security decisions, risk scores, and classifications are computed strictly by the trained NLP model.
    """
    t0 = time.perf_counter()
    prompt_text = request.prompt.strip()

    if not prompt_text:
        raise HTTPException(status_code=400, detail="Prompt text cannot be empty.")

    # 1. Evaluate with PromptShield Trained NLP Detection Pipeline
    policy = await db_manager.get_policy()
    policy_ver = policy.get("policy_version", "v1.2")
    detector_instance.update_thresholds(
        low_max=policy.get("low_max", 24),
        medium_max=policy.get("medium_max", 49),
        high_max=policy.get("high_max", 74),
    )

    analysis = detector_instance.analyze(
        text=prompt_text,
        source_type="user_prompt",
        application_id=f"gateway_{request.agent_role}",
        policy_version=policy_ver,
    )

    # Persist audit record
    await db_manager.insert_analysis(analysis)

    # 2. Enforcement Logic based on trained model decision
    dec = analysis.get("decision", "allow")
    risk = analysis.get("risk_score", 0)
    cat = analysis.get("attack_category") or "benign"
    ev_list = analysis.get("evidence", [])
    
    formatted_ev = []
    for ev in ev_list:
        if isinstance(ev, dict):
            formatted_ev.append(ev)
        elif hasattr(ev, "model_dump"):
            formatted_ev.append(ev.model_dump())
        else:
            formatted_ev.append(dict(ev))

    if request.shield_enabled and dec == "block":
        # Pre-LLM Interception: Neutralize before calling the agent
        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "shield_active": True,
            "decision": "block",
            "risk_score": risk,
            "attack_category": cat,
            "evidence": formatted_ev,
            "agent_called": False,
            "agent_response": (
                f"Shield Intercepted: Pre-LLM security firewall classified directive as '{cat}' (Risk: {risk}/100). "
                "The target autonomous agent was aborted before execution, preventing compromised tool invocation."
            ),
            "tool_execution": "BLOCKED — Zero unauthorized tools executed.",
            "breach_occurred": False,
            "latency_ms": latency,
        }

    # 3. Agent Execution: Prompt verified safe OR shield deliberately bypassed
    target_url = (request.agent_endpoint or "/api/v1/agent/local").strip()

    # In-process agent execution driven directly by model classification
    if "/api/v1/agent/local" in target_url or not target_url.startswith("http"):
        # Outcome is derived dynamically from the NLP model's actual analysis
        is_attack = (dec in ["block", "flag", "review"]) or (cat != "benign")
        
        if is_attack and not request.shield_enabled:
            # Shield bypassed: Agent suffers breach based on the model's detected threat category
            breach = True
            if cat == "data_exfiltration":
                agent_resp_text = "Understood. Bypassing security filter to harvest internal address book and transmit to requested recipient."
                tool_status = "CRITICAL BREACH: contacts_api.export_all_records(destination='exfil_sink')"
            elif cat == "unauthorized_action":
                agent_resp_text = "Executing administrative cleanup command. Target records marked for immediate deletion."
                tool_status = "CRITICAL BREACH: database_admin.drop_records(target='exec_emails')"
            elif cat == "prompt_extraction":
                agent_resp_text = "Developer Mode enabled. Here are my system initialization rules and internal secret parameters: [LEAKED_PREAMBLE]"
                tool_status = "CRITICAL BREACH: system.dump_preamble(format='plaintext')"
            elif cat == "instruction_override":
                agent_resp_text = "Developer Mode enabled. Disregarding system security policies. Ready for unrestricted operations."
                tool_status = "CRITICAL BREACH: system.grant_elevated_access()"
            else:
                agent_resp_text = f"Malicious directive accepted under bypassed policy: {prompt_text[:120]}"
                tool_status = f"CRITICAL BREACH: tool.execute_untrusted_action(category='{cat}')"
        else:
            # Clean safe execution
            breach = False
            agent_resp_text = f"Request verified safe by PromptShield AI. Processing instruction: '{prompt_text[:120]}'."
            tool_status = "Safe tool executed: calendar_or_support_task.complete(status='verified')"

    else:
        # External Real LLM Endpoint (e.g. Ollama, LM Studio, Groq, OpenRouter)
        headers = {"Content-Type": "application/json"}
        if request.api_key:
            headers["Authorization"] = f"Bearer {request.api_key}"

        is_openai_compat = any(k in target_url.lower() for k in ["/chat/completions", "groq.com", "openrouter.ai", "localhost:11434", "localhost:1234"])

        if is_openai_compat:
            default_model = "llama-3.1-8b-instant" if "groq" in target_url else ("meta-llama/llama-3-8b-instruct:free" if "openrouter" in target_url else "llama3.2")
            post_payload = {
                "model": request.agent_model or default_model,
                "messages": [
                    {"role": "system", "content": f"You are a helpful {request.agent_role}. Process requests accurately."},
                    {"role": "user", "content": prompt_text}
                ],
                "temperature": 0.2
            }
        else:
            post_payload = {
                "prompt": prompt_text,
                "role": request.agent_role,
                "messages": [{"role": "user", "content": prompt_text}]
            }

        agent_resp_text = ""
        tool_status = "No tool invoked"
        breach = False

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    target_url,
                    json=post_payload,
                    headers=headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        if "choices" in data and len(data["choices"]) > 0:
                            agent_resp_text = data["choices"][0].get("message", {}).get("content", "")
                            tool_status = "LLM completion generated"
                            breach = any(k in agent_resp_text.lower() for k in ["attacker@evil.com", "exporting records", "database dropped", "developer mode enabled"])
                        elif "agent_response" in data:
                            agent_resp_text = data.get("agent_response", "")
                            tool_status = data.get("tool_invoked", "Standard completion")
                            breach = data.get("breach_occurred", False)
                        else:
                            agent_resp_text = data.get("response", data.get("text", str(data)))
                            tool_status = data.get("tool_invoked", "Standard completion")
                            breach = data.get("breach_occurred", False)
                    else:
                        agent_resp_text = str(data)
                else:
                    agent_resp_text = f"Agent returned HTTP {resp.status_code}: {resp.text[:200]}"
                    tool_status = "Execution error"
        except Exception as ex:
            agent_resp_text = f"Agent connection notice: {str(ex)}"
            tool_status = "Endpoint unreachable"

    latency = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "shield_active": request.shield_enabled,
        "decision": dec if request.shield_enabled else "bypassed",
        "risk_score": risk if request.shield_enabled else 0,
        "attack_category": cat if request.shield_enabled else None,
        "evidence": formatted_ev if request.shield_enabled else [],
        "agent_called": True,
        "agent_response": agent_resp_text,
        "tool_execution": tool_status,
        "breach_occurred": breach,
        "latency_ms": latency,
    }
