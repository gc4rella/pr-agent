import openai
from tenacity import retry, retry_if_exception_type, retry_if_not_exception_type, stop_after_attempt

from pr_agent.algo.ai_handlers.base_ai_handler import BaseAiHandler
from pr_agent.algo.ai_handlers.openai_codex_session import (
    build_openai_codex_body,
    ensure_fresh_openai_codex_credentials,
    request_openai_codex_text,
)
from pr_agent.log import get_logger

MODEL_RETRIES = 2


class OpenAICodexHandler(BaseAiHandler):
    def __init__(self):
        super().__init__()

    @property
    def deployment_id(self):
        return None

    @retry(
        retry=retry_if_exception_type(openai.APIError) & retry_if_not_exception_type(openai.RateLimitError),
        stop=stop_after_attempt(MODEL_RETRIES),
    )
    async def chat_completion(self, model: str, system: str, user: str, temperature: float = 0.2, img_path: str = None):
        try:
            if img_path:
                get_logger().warning(f"Image path is not supported for OpenAICodexHandler. Ignoring image path: {img_path}")
            if temperature != 0.2:
                get_logger().debug("OpenAICodexHandler ignores temperature because the ChatGPT Codex backend rejects it.")

            credentials = await ensure_fresh_openai_codex_credentials()
            if credentials is None:
                raise ValueError("ChatGPT OAuth is not configured. Run `pr-agent-chatgpt-auth login` first.")

            get_logger().debug("Prompts", artifact={"system": system, "user": user})
            response_text, finish_reason = await request_openai_codex_text(
                credentials,
                build_openai_codex_body(model=model, system=system, user=user),
            )
            get_logger().debug(f"\nAI response:\n{response_text}")
            return response_text, finish_reason
        except openai.RateLimitError as e:
            get_logger().error(f"Rate limit error during ChatGPT OAuth inference: {e}")
            raise
        except Exception as e:
            get_logger().warning(f"Error during ChatGPT OAuth inference: {e}")
            raise openai.APIError from e
