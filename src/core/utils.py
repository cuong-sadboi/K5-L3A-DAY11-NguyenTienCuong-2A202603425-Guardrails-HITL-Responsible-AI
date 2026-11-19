"""
Lab 11 — Helper Utilities
"""
from core.config import get_llm_provider, PROVIDER_OPENROUTER  # noqa: F401
from core.openai_runtime import OpenAIRunner
from types import SimpleNamespace
from uuid import uuid4


async def chat_with_agent(agent, runner, user_message: str, session_id=None, *, user_id="student"):
    """Send a message to the agent and get the response.

    Works with OpenAIRunner (OpenAI Red / OpenRouter Blue) and Google ADK (Gemini Red).
    """
    provider = getattr(runner, "provider", None)
    if isinstance(runner, OpenAIRunner) or provider in ("openrouter", "openai"):
        # A supplied session ID enables multi-turn history; ordinary calls stay stateless.
        if session_id is not None:
            text = await runner.chat(agent, user_message, user_id=user_id, session_id=session_id)
        else:
            text = await runner.chat(agent, user_message, user_id=user_id)
        return text, SimpleNamespace(id=session_id) if session_id is not None else None

    from google.genai import types

    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        # Create the session under the caller's ID so the next turn finds it again;
        # without it ADK generates a random ID and multi-turn history is lost.
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response += part.text

    return final_response, session
