from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError


class NmapScannerProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            # Check if sudo password is provided for privileged scans (optional)
            if credentials.get("sudo_password"):
                # Validate sudo password format (basic check)
                if not isinstance(credentials["sudo_password"], str):
                    raise ToolProviderCredentialValidationError(
                        "Sudo password must be a string"
                    )

            # Check rate limiting settings (optional)
            if credentials.get("max_parallelism"):
                max_parallel = credentials["max_parallelism"]
                if not isinstance(max_parallel, (int, str)):
                    raise ToolProviderCredentialValidationError(
                        "Max parallelism must be a number"
                    )
                if isinstance(max_parallel, str):
                    try:
                        int(max_parallel)
                    except ValueError:
                        raise ToolProviderCredentialValidationError(
                            "Max parallelism must be a valid number"
                        )

        except ToolProviderCredentialValidationError:
            raise
        except Exception as e:
            raise ToolProviderCredentialValidationError(str(e))
