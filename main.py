from dify_plugin import Plugin, DifyPluginEnv

plugin = Plugin(DifyPluginEnv(MAX_REQUEST_TIMEOUT=300))  # 5 minutes for complex scans

if __name__ == '__main__':
    plugin.run()
