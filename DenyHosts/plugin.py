import logging
import os
import subprocess
import shlex

error = logging.getLogger("plugin").error
info = logging.getLogger("plugin").info
debug = logging.getLogger("plugin").debug


def execute(executable, hosts):
    for host in hosts:
        debug('invoking plugin: {0} {1}'.format(executable, host))
        try:
            # 安全执行插件
            result = subprocess.run(
                [executable, host],
                check=False,  # 插件可能返回非零
                capture_output=True,
                timeout=30,
                text=True
            )
            if result.returncode:
                info('plugin returned {0}'.format(result.returncode))
                if result.stderr:
                    debug('plugin stderr: {0}'.format(result.stderr))
        except subprocess.TimeoutExpired:
            error('plugin timed out: {0}'.format(executable))
        except Exception as e:
            error('plugin error: {0}'.format(e))
