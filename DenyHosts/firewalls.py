import logging
import os
import subprocess
import shlex

logger = logging.getLogger("firewalls")
debug = logger.debug
info = logger.info
error = logger.error
exception = logger.exception
warning = logger.warning


class IpTables(object):

    def __init__(self, prefs):
        self.__blockport = prefs.get("BLOCKPORT")
        self.__iptables = prefs.get("IPTABLES")
        # New: optional explicit ip6tables path; fallback to 'ip6tables'
        self.__ip6tables = prefs.get("IP6TABLES") or "ip6tables"

    def _execute_command(self, cmd: str, args: list) -> bool:
        """安全执行命令"""
        try:
            result = subprocess.run(
                [cmd] + args,
                check=True,
                capture_output=True,
                timeout=30,
                text=True
            )
            debug(f"Command succeeded: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            error(f"Command failed: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            error("Command timed out")
            return False
        except Exception as e:
            error(f"Execution error: {e}")
            return False

    @staticmethod
    def __is_ipv6(ip):
        # Fast heuristic: IPv6 has ':' and not an IPv4-mapped prefix we treat as v4
        return (':' in ip) and (not ip.startswith('::ffff:'))

    def block_ips(self, ip_list):
        info("Creating new iptable rules for %s ips" % len(ip_list))
        try:
            for ip in ip_list:
                block_ip = str(ip)
                use_v6 = self.__is_ipv6(block_ip)
                rule_parts = self.__create_rule_parts(block_ip, use_v6)
                info("Creating new firewall rule %s", ' '.join(rule_parts))
                if not self._execute_command(rule_parts[0], rule_parts[1:]):
                    error(f"Failed to block IP: {block_ip}")
        except Exception as e:
            msg = 'Unable to write new firewall rule with error: %s' % e
            print(msg)
            exception(msg)

    def __create_rule_parts(self, block_ip, v6=False):
        debug("Creating %s rule for %s" % ("ip6tables" if v6 else "iptables", block_ip))
        if self.__blockport is not None and ',' in self.__blockport:
            rule = self.__create_multiport_rule(block_ip)
        elif self.__blockport:
            rule = self.__create_singleport_rule(block_ip)
        else:
            rule = self.__create_block_all_rule(block_ip)
        cmd = self.__ip6tables if v6 else self.__iptables
        return [cmd, '-I'] + shlex.split(rule)

    def __create_singleport_rule(self, block_ip):
        debug("Generating INPUT block single port rule")
        sp_rule = "INPUT -p tcp --dport %s -s %s -j DROP" % \
                  (self.__blockport, block_ip)
        return sp_rule

    def __create_multiport_rule(self, block_ip):
        debug("Generating INPUT block multi-port rule")
        mp_rule = "INPUT -p tcp -m multiport --dports %s -s %s -j DROP" % \
                  (self.__blockport, block_ip)
        return mp_rule

    def __create_block_all_rule(self, block_ip):
        debug("Generating INPUT block all ports rule")
        ba_rule = "INPUT -s %s -j DROP" % (block_ip)
        return ba_rule

    def remove_ips(self, ip_list):
        info("Removing %s ips from iptables rules" % len(ip_list))
        try:
            for ip in ip_list:
                blocked_ip = str(ip)
                use_v6 = self.__is_ipv6(blocked_ip)
                remove_rule_parts = self.__remove_ip_rule_parts(blocked_ip, use_v6)
                info('Removing ip rule for %s' % blocked_ip)
                if not self._execute_command(remove_rule_parts[0], remove_rule_parts[1:]):
                    error(f"Failed to remove IP: {blocked_ip}")
        except Exception as e:
            msg = 'Unable to remove firewall rule with error: %s' % e
            print(msg)
            exception(msg)

    def __remove_ip_rule_parts(self, blocked_ip, v6=False):
        debug("Creating %s remove rule for %s" % ("ip6tables" if v6 else "iptables", blocked_ip))
        if self.__blockport is not None and ',' in self.__blockport:
            rule = self.__create_multiport_rule(blocked_ip)
        elif self.__blockport:
            rule = self.__create_singleport_rule(blocked_ip)
        else:
            rule = self.__create_block_all_rule(blocked_ip)
        cmd = self.__ip6tables if v6 else self.__iptables
        return [cmd, '-D'] + shlex.split(rule)
