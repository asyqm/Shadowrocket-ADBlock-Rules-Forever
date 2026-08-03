# -*- coding: utf-8 -*-

import ipaddress
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PROFILE_OUTPUT = ROOT.parent / 'clash_verge_whitelist.yaml'
BITZNET_RULES_OUTPUT = ROOT.parent / 'clash_verge_bitznet_rules.yaml'


def is_ip_network(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def rule_type(value):
    if is_ip_network(value):
        return 'IP-CIDR6' if ':' in value else 'IP-CIDR'
    if '.' not in value and len(value) > 1:
        return 'DOMAIN-KEYWORD'
    return 'DOMAIN-SUFFIX'


def read_rules(path, policy):
    rules = []
    for raw_line in (ROOT / path).read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('#'):
            rules.append(line)
            continue

        value = line
        kind = rule_type(value)
        if kind in ('IP-CIDR', 'IP-CIDR6') and '/' not in value:
            value += '/128' if kind == 'IP-CIDR6' else '/32'

        suffix = ',no-resolve' if kind in ('IP-CIDR', 'IP-CIDR6') else ''
        rules.append(f'{kind},{value},{policy}{suffix}')
    return rules


def append_unique(target, seen, rules):
    for rule in rules:
        if rule.startswith('#'):
            target.append(rule)
            continue
        if rule in seen:
            continue
        seen.add(rule)
        target.append(rule)


def render_rules(proxy_policy, include_fallback):
    rules = []
    seen = set()

    append_unique(rules, seen, read_rules('resultant/ad.list', 'REJECT'))
    append_unique(rules, seen, read_rules('manual_reject.txt', 'REJECT'))

    append_unique(rules, seen, read_rules('manual_direct.txt', 'DIRECT'))

    append_unique(rules, seen, read_rules('manual_proxy.txt', proxy_policy))
    append_unique(rules, seen, read_rules('manual_gfwlist.txt', proxy_policy))

    append_unique(rules, seen, read_rules('resultant/top500_direct.list', 'DIRECT'))
    append_unique(rules, seen, read_rules('resultant/gfw.list', proxy_policy))

    rules.extend([
        '# Apple News',
        f'DOMAIN-SUFFIX,apple.news,{proxy_policy}',
        f'DOMAIN-SUFFIX,news-edge.apple.com,{proxy_policy}',
        f'DOMAIN-SUFFIX,news-events.apple.com,{proxy_policy}',
        '# China direct',
        'DOMAIN-SUFFIX,cn,DIRECT',
        'GEOIP,CN,DIRECT',
    ])

    if include_fallback:
        rules.extend([
            '# Fallback proxy',
            f'MATCH,{proxy_policy}',
        ])

    return rules


def indent_list(rules, spaces=2):
    prefix = ' ' * spaces
    lines = []
    for rule in rules:
        if rule.startswith('#'):
            lines.append(f'{prefix}{rule}')
        else:
            lines.append(f'{prefix}- {rule}')
    return '\n'.join(lines)


def render_profile():
    rules = render_rules(proxy_policy='PROXY', include_fallback=True)
    content = f"""# Clash Verge / Mihomo 配置
# Generated from Shadowrocket-ADBlock-Rules-Forever at {time.strftime("%Y-%m-%d %H:%M:%S")}
#
# 使用方法：
# 1. 将 proxy-providers.subscription.url 替换为你的节点订阅地址。
# 2. 在 Clash Verge 中导入本 YAML。
# 3. 默认策略为国内直连、广告拒绝、未知境外流量走代理，更适合 Slack/附件上传这类境外服务。

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  sniff:
    TLS:
      ports:
        - 443
        - 8443
    HTTP:
      ports:
        - 80
        - 8080-8880
      override-destination: true

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - localhost.ptlogin2.qq.com

proxy-providers:
  subscription:
    type: http
    url: https://example.com/replace-with-your-subscription
    path: ./providers/subscription.yaml
    interval: 86400
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 600

proxy-groups:
  - name: PROXY
    type: select
    use:
      - subscription
    proxies:
      - AUTO
      - DIRECT
  - name: AUTO
    type: url-test
    use:
      - subscription
    url: https://www.gstatic.com/generate_204
    interval: 600
    tolerance: 50

rules:
{indent_list(rules)}
"""
    PROFILE_OUTPUT.write_text(content, encoding='utf-8')


def render_bitznet_rules():
    rules = render_rules(proxy_policy='Bitz Net', include_fallback=False)
    content = f"""# Clash Verge Profile Enhancement Rules
# Generated from Shadowrocket-ADBlock-Rules-Forever at {time.strftime("%Y-%m-%d %H:%M:%S")}
#
# 使用方法：
# 1. 保留 Clash Verge 中现有的 Bitz+Net 订阅。
# 2. 在 Bitz+Net 订阅的 Rules Enhancement/编辑规则中使用本文件内容。
# 3. 本文件只前插规则，不包含节点和最终 MATCH，避免覆盖原订阅的节点与兜底规则。

prepend:
{indent_list(rules)}

append: []

delete: []
"""
    BITZNET_RULES_OUTPUT.write_text(content, encoding='utf-8')


def main():
    render_profile()
    render_bitznet_rules()


if __name__ == '__main__':
    main()
