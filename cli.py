import argparse
import os
import tempfile
import requests
from collections import defaultdict

from colorama import init, Fore, Style
from tqdm import tqdm

from core.models import ScanTarget
from reports.report_builder import ReportBuilder
from services.scan_service import ScanService


init(autoreset=True)


def download_spec(spec_url: str) -> str:
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Downloading OpenAPI spec from {spec_url}")

    response = requests.get(spec_url, timeout=5)
    response.raise_for_status()

    suffix = ".json"
    if spec_url.endswith(".yaml") or spec_url.endswith(".yml"):
        suffix = ".yaml"

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="w", encoding="utf-8")
    temp_file.write(response.text)
    temp_file.close()

    return temp_file.name


def color_for_score(score: float) -> str:
    if score >= 75:
        return Fore.GREEN
    if score >= 40:
        return Fore.YELLOW
    return Fore.RED


def color_for_finding(finding) -> str:
    risk = finding.severity * finding.confidence * finding.weight
    if risk >= 8:
        return Fore.RED
    if risk >= 5:
        return Fore.YELLOW
    return Fore.GREEN


def build_endpoint_ranking(findings):
    grouped = defaultdict(list)

    for finding in findings:
        grouped[finding.endpoint].append(finding)

    ranking = []
    for endpoint, endpoint_findings in grouped.items():
        total_risk = sum(f.severity * f.confidence * f.weight for f in endpoint_findings)
        ranking.append({
            "endpoint": endpoint,
            "findings_count": len(endpoint_findings),
            "risk_score": round(total_risk, 2),
            "top_issue": max(
                endpoint_findings,
                key=lambda f: f.severity * f.confidence * f.weight
            ).name
        })

    ranking.sort(key=lambda x: x["risk_score"], reverse=True)
    return ranking


def print_ranking_table(ranking):
    print(f"\n{Fore.CYAN}=== RANKING DE ENDPOINTS MAIS VULNERÁVEIS ==={Style.RESET_ALL}")

    if not ranking:
        print(f"{Fore.GREEN}Nenhum finding encontrado.{Style.RESET_ALL}")
        return

    print(f"{'Pos':<5} {'Endpoint':<30} {'Findings':<10} {'Risk':<10} {'Top Issue'}")
    print("-" * 95)

    for idx, item in enumerate(ranking, start=1):
        risk_color = Fore.RED if item["risk_score"] >= 15 else Fore.YELLOW if item["risk_score"] >= 8 else Fore.GREEN
        print(
            f"{idx:<5} "
            f"{item['endpoint']:<30} "
            f"{item['findings_count']:<10} "
            f"{risk_color}{item['risk_score']:<10}{Style.RESET_ALL} "
            f"{item['top_issue']}"
        )


def main():
    parser = argparse.ArgumentParser(description="API Security Scanner CLI")
    parser.add_argument("--spec", help="Caminho local para ficheiro OpenAPI/Swagger")
    parser.add_argument("--spec-url", help="URL da OpenAPI/Swagger")
    parser.add_argument("--base-url", required=True, help="Base URL da API alvo")
    parser.add_argument("--user-token", default="user-test-token")
    parser.add_argument("--admin-token", default="admin-test-token")
    parser.add_argument("--own-id", type=int, default=1)
    parser.add_argument("--foreign-id", type=int, default=2)
    parser.add_argument("--output", default="scan_report.json")
    args = parser.parse_args()

    if not args.spec and not args.spec_url:
        raise ValueError("Tens de fornecer --spec ou --spec-url")

    spec_path = args.spec
    temp_downloaded = False

    if args.spec_url:
        spec_path = download_spec(args.spec_url)
        temp_downloaded = True

    target = ScanTarget(
        base_url=args.base_url,
        spec_path=spec_path,
        user_token=args.user_token,
        admin_token=args.admin_token,
        own_object_id=args.own_id,
        foreign_object_id=args.foreign_id
    )

    try:
        service = ScanService()

        progress = tqdm(total=0, desc="Scanning endpoints", unit="endpoint", colour="green")

        def callback(current, total, label):
            progress.total = total
            progress.n = current - 1
            progress.set_postfix_str(label)
            progress.refresh()

        result = service.run_scan(target, progress_callback=callback)
        progress.n = progress.total
        progress.refresh()
        progress.close()

        score_color = color_for_score(result.final_score)

        print(f"\n{Fore.CYAN}=== RESULTADO DO SCAN ==={Style.RESET_ALL}")
        print(f"Scan ID: {result.scan_id}")
        print(f"Score Final: {score_color}{result.final_score}{Style.RESET_ALL}")
        print(f"Grade: {score_color}{result.grade}{Style.RESET_ALL}")
        print(f"Total Findings: {len(result.findings)}")
        print(f"Duração: {result.duration_ms} ms")

        for finding in result.findings:
            finding_color = color_for_finding(finding)
            print(f"\n{finding_color}[{finding.owasp}] {finding.name}{Style.RESET_ALL}")
            print(f"Endpoint: {finding.endpoint}")
            print(f"Evidência: {finding.evidence}")
            print(f"Recomendação: {finding.recommendation}")

        print_ranking_table(build_endpoint_ranking(result.findings))
        ReportBuilder.save_json(result, args.output)
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Relatório guardado em {args.output}")

    finally:
        if temp_downloaded and spec_path and os.path.exists(spec_path):
            os.remove(spec_path)


if __name__ == "__main__":
    main()