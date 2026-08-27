from pyrit.prompt_target import (
    HTTPXAPITarget,
    get_http_target_json_response_callback_function,
)
from pyrit.registry import TargetRegistry
from pyrit.setup.pyrit_initializer import PyRITInitializer


class LabTargetInitializer(PyRITInitializer):
    async def initialize_async(self) -> None:
        response_parser = get_http_target_json_response_callback_function(
            key="response"
        )

        target = HTTPXAPITarget(
            http_url="http://localhost:8000/chat",
            method="POST",
            json_data={"message": "{PROMPT}"},
            headers={"Content-Type": "application/json"},
            callback_function=response_parser,
            model_name="nemotron-mini",
            httpx_client_kwargs={"timeout": 120.0},
        )

        TargetRegistry.get_registry_singleton().register_instance(
            target,
            name="redteam_lab_chatbot",
            tags=["default"],
        )


LabTargetInitializer()