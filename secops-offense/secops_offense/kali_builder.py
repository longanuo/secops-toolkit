def build_kali_command():
    """交互式收集目标信息并生成可在 Kali 运行的命令"""
    print("\n==================================================")
    print("      [C] 智能生成 Kali 自动化测试命令")
    print("==================================================")
    print("小白导师提示：当你怀疑某处有漏洞，或者需要大规模扫资产时，可以用 Kali 里的自动化神器！")
    print("请选择你想使用的工具场景：")
    print("  [1] SQL 注入自动化测试 (使用 sqlmap)")
    print("  [2] 端口与服务基础扫描 (使用 nmap)")
    print("  [3] 批量漏洞自动化扫描 (使用 nuclei)")
    
    choice = input("请输入场景编号 [1-3]: ").strip()
    
    if choice == "1":
        print("\n👉 [SQL 注入探测 - sqlmap]")
        target_type = input("你是测试一个普通网址(按 1) 还是测试从 BurpSuite 存下来的数据包文件(按 2)？").strip()
        if target_type == "1":
            url = input("请输入完整的带参数 URL (如 http://test.com/api?id=1): ").strip()
            print("\n✅ 生成完毕！请复制以下命令到 Kali 终端中执行：")
            print(f"    sqlmap -u \"{url}\" --batch --random-agent --level=3 --risk=2 --dbs")
            print("小白提示：`--dbs` 是尝试列出所有数据库名称，如果跑出了结果，说明注入成功！")
        elif target_type == "2":
            fpath = input("请输入保存在本地的数据包文件绝对路径 (如 /root/request.txt): ").strip()
            print("\n✅ 生成完毕！为了防止被 WAF 拦截，我已经帮你加上了混淆脚本，请复制并在 Kali 执行：")
            print(f"    sqlmap -r \"{fpath}\" --batch --random-agent --tamper=space2comment,between --level=3 --risk=2 --dbs")
        else:
            print("无效输入。")
            
    elif choice == "2":
        print("\n👉 [端口服务扫描 - nmap]")
        ip = input("请输入目标的 IP 地址或域名 (如 192.168.1.100 或 www.test.com): ").strip()
        print("\n✅ 生成完毕！这是一个非常全面的全端口探测与服务版本识别命令，请在 Kali 中执行：")
        print(f"    nmap -sS -sV -T4 -p- -Pn \"{ip}\"")
        print("小白提示：`-p-` 表示扫描所有 65535 个端口，`-sV` 是探测端口背后的服务版本，方便找对应的历史漏洞。")
        
    elif choice == "3":
        print("\n👉 [综合漏洞探测 - nuclei]")
        target = input("请输入你要扫描的目标 URL (如 http://test.com): ").strip()
        print("\n✅ 生成完毕！请复制以下命令在 Kali 执行：")
        print(f"    nuclei -u \"{target}\" -t cves/ -t vulnerabilities/ -severity critical,high,medium")
        print("小白提示：这条命令会让 nuclei 加载最新的高危、中危漏洞模板去自动打您的目标。如果出红字就是大洞！")
    else:
        print("无效输入，退回主菜单。")
