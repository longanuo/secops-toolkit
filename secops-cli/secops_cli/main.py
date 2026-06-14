"""SecOps 统一命令行入口"""
import sys
import argparse


def print_logo():
    logo = """
==================================================
        SecOps 自动化安全运维工具箱 v3.0.0
        渗透测试 + 系统维护 + 智能防御
==================================================
    """
    print(logo)


def show_main_menu():
    print("==================================================")
    print("  [进攻方向 - 漏洞检测]")
    print("    [1] 漏洞自动验证引擎 (输入 URL 自动攻击测试)")
    print("    [2] 在线目标主动渗透辅助测试")
    print("    [3] 获取免杀 Payload 与测试弹药")
    print("    [4] 智能生成 Kali 自动化测试命令")
    print("    [5] 挖洞思路与 Checklist 导师指引")
    print("    [6] GitHub 攻防仓库自动学习")
    print("    [11] WAF 指纹检测与绕过测试")
    print()
    print("  [防御方向 - 系统安全]")
    print("    [7] 运行系统安全体检")
    print("    [8] 执行一键安全加固 (需要管理员/Root权限)")
    print("    [9] 更新防火墙与威胁情报 (仅支持Linux nftables)")
    print("    [10] 生成与导出安全报告 (HTML / Markdown)")
    print("    [12] 异常行为检测 (暴力破解/可疑进程)")
    print("    [13] 威胁情报聚合与分析")
    print()
    print("    [0] 退出工具箱")
    print("==================================================")


def run_interactive():
    from secops_core import utils

    print_logo()
    print(f"当前系统: {utils.platform.system()} ({utils.platform.release()})")
    print(f"特权权限: {'已获取' if utils.is_admin() else '未获取 (部分功能受限)'}")
    print()

    last_scan_data = None

    while True:
        show_main_menu()

        try:
            choice = input("请输入选项数字 [0-13]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n退出工具箱。")
            break

        if choice == "0":
            print("退出工具箱。")
            break

        # === 进攻方向 ===
        elif choice == "1":
            from secops_offense.attack_engine import start_attack
            start_attack()
            input("\n按回车键继续...")

        elif choice == "2":
            from secops_offense.online_scanner import start_online_testing
            start_online_testing()
            input("\n按回车键继续...")

        elif choice == "3":
            from secops_offense.arsenal import print_arsenal
            cat = input("请输入漏洞类别 (XSS/SQLi/SSRF/RCE/JWT/CORS，留空查看全部): ").strip()
            print_arsenal(cat if cat else None)
            input("\n按回车键继续...")

        elif choice == "4":
            from secops_offense.kali_builder import build_kali_command
            build_kali_command()
            input("\n按回车键继续...")

        elif choice == "5":
            from secops_offense.guide import print_guide
            print_guide()
            input("\n按回车键继续...")

        elif choice == "6":
            from secops_offense.github_offense import run_offense_learning
            force = input("是否强制刷新缓存？(y/n): ").strip().lower() == 'y'
            run_offense_learning(force=force)
            input("\n按回车键继续...")

        elif choice == "11":
            from secops_defense.waf import detect_waf
            url = input("请输入目标 URL: ").strip()
            if not url.startswith("http"):
                url = "https://" + url
            print(f"\n[*] 正在检测 WAF 指纹...")
            wafs = detect_waf(url)
            if wafs:
                print(f"\n[+] 检测到 {len(wafs)} 个 WAF:")
                for waf in wafs:
                    print(f"    - {waf['name']} (置信度: {waf['confidence']})")
            else:
                print("\n[-] 未检测到 WAF")
            input("\n按回车键继续...")

        # === 防御方向 ===
        elif choice == "7":
            from secops_defense import evaluator
            print("\n正在运行系统安全体检...")
            last_scan_data = evaluator.run_evaluation()
            print("\n安全体检完成！可选择 [10] 导出详细成果报告。")
            input("\n按回车键继续...")

        elif choice == "8":
            from secops_core import utils
            if not utils.is_admin():
                print("\n[错误] 执行安全加固需要管理员/Root权限。")
            elif utils.is_windows():
                from secops_defense import hardener
                print("\n正在执行 Windows 安全加固...")
                success = hardener.run_hardening()
                print(f"\n[{'成功' if success else '失败'}] 加固{'已成功应用' if success else '执行中遇到错误'}。")
            else:
                from secops_defense import hardener
                print("\n正在执行 Linux 系统安全一键加固配置...")
                success = hardener.run_hardening()
                print(f"\n[{'成功' if success else '失败'}] 加固{'已成功应用' if success else '执行中遇到错误'}。")
            input("\n按回车键继续...")

        elif choice == "9":
            from secops_core import utils
            if utils.is_windows():
                print("\n[提示] Windows 防火墙更新中...")
                from secops_defense import firewall
                firewall.update_threat_intel_firewall()
            elif not utils.is_admin():
                print("\n[错误] 更新防火墙需要 Root 权限。")
            else:
                from secops_defense import firewall
                print("\n正在从网络同步威胁情报并更新 nftables...")
                success = firewall.update_threat_intel_firewall()
                print(f"\n[{'成功' if success else '失败'}] 防火墙更新{'完成' if success else '失败'}。")
            input("\n按回车键继续...")

        elif choice == "10":
            from secops_defense import evaluator, reporter
            if last_scan_data is None:
                print("\n正在执行安全体检...")
                last_scan_data = evaluator.run_evaluation()
            html_path, md_path = reporter.generate_reports(last_scan_data)
            print(f"\n报告已导出:")
            print(f"  HTML: {html_path}")
            print(f"  Markdown: {md_path}")
            input("\n按回车键继续...")

        elif choice == "12":
            from secops_defense.anomaly import run_anomaly_detection
            print("\n正在执行异常行为检测...")
            anomalies = run_anomaly_detection()
            if anomalies:
                print(f"\n[!] 检测到 {len(anomalies)} 个异常:")
                for a in anomalies:
                    print(f"    [{a['severity']}] {a['description']}")
            else:
                print("\n[+] 未检测到异常行为")
            input("\n按回车键继续...")

        elif choice == "13":
            from secops_defense.threat_intel import get_threat_summary
            print("\n正在获取威胁情报摘要...")
            summary = get_threat_summary()
            print(f"\n威胁情报摘要:")
            print(f"  总计: {summary['total']} 条")
            print(f"  严重: {summary['critical']} 条")
            print(f"  高危: {summary['high']} 条")
            print(f"  中危: {summary['medium']} 条")
            print(f"  低危: {summary['low']} 条")
            if summary['last_update']:
                print(f"  最后更新: {summary['last_update']}")
            else:
                print(f"  最后更新: 无数据")
            input("\n按回车键继续...")

        else:
            print("无效选项，请重新输入。")


def main():
    parser = argparse.ArgumentParser(description="SecOps 自动化安全运维工具箱 v3.0.0")
    parser.add_argument("--check", action="store_true", help="运行系统安全体检")
    parser.add_argument("--harden", action="store_true", help="执行一键安全加固")
    parser.add_argument("--update-firewall", action="store_true", help="更新防火墙威胁情报")
    parser.add_argument("--attack", type=str, help="对指定 URL 启动漏洞验证引擎")
    parser.add_argument("--browser", action="store_true", help="使用浏览器引擎 (SPA 模式)")
    parser.add_argument("--learn", action="store_true", help="从 GitHub 学习攻防 payload")
    parser.add_argument("--cron-check", action="store_true", help="定时巡检 (供 cron 调用)")
    parser.add_argument("--waf", type=str, help="检测目标 WAF 指纹")
    parser.add_argument("--anomaly", action="store_true", help="运行异常行为检测")
    parser.add_argument("--intel", action="store_true", help="查看威胁情报摘要")

    args = parser.parse_args()

    if args.check:
        from secops_defense import evaluator
        data = evaluator.run_evaluation()
        print(f"\n安全评分: {data['score']} / 100")
    elif args.harden:
        from secops_core import utils
        from secops_defense import hardener
        if not utils.is_admin():
            print("[错误] 需要管理员/Root 权限。")
            sys.exit(1)
        hardener.run_hardening()
    elif args.update_firewall:
        from secops_defense import firewall
        firewall.update_threat_intel_firewall()
    elif args.attack:
        from secops_offense.attack_engine import start_attack
        start_attack(args.attack, browser_mode=args.browser)
    elif args.learn:
        from secops_offense.github_offense import run_offense_learning
        run_offense_learning()
    elif args.cron_check:
        from secops_defense import cron
        cron.run_cron_check()
    elif args.waf:
        from secops_defense.waf import detect_waf
        wafs = detect_waf(args.waf)
        if wafs:
            print(f"检测到 {len(wafs)} 个 WAF:")
            for waf in wafs:
                print(f"  - {waf['name']} (置信度: {waf['confidence']})")
        else:
            print("未检测到 WAF")
    elif args.anomaly:
        from secops_defense.anomaly import run_anomaly_detection
        anomalies = run_anomaly_detection()
        if anomalies:
            print(f"检测到 {len(anomalies)} 个异常:")
            for a in anomalies:
                print(f"  [{a['severity']}] {a['description']}")
        else:
            print("未检测到异常行为")
    elif args.intel:
        from secops_defense.threat_intel import get_threat_summary
        summary = get_threat_summary()
        print(f"威胁情报摘要:")
        print(f"  总计: {summary['total']} 条")
        print(f"  严重: {summary['critical']} 条")
        print(f"  高危: {summary['high']} 条")
        print(f"  中危: {summary['medium']} 条")
        print(f"  低危: {summary['low']} 条")
    else:
        run_interactive()


if __name__ == "__main__":
    main()
