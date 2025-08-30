from dify_plugin import Plugin, DifyPluginEnv
import asyncio
import logging

# Configure logging for better debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Increase timeout for complex scans
plugin = Plugin(DifyPluginEnv(
    MAX_REQUEST_TIMEOUT=600,  # 10 minutes
    ENABLE_ASYNC=True,
    MAX_WORKERS=10
))

if __name__ == '__main__':
    plugin.run()
