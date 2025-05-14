import os
import sys
import json
import subprocess
import argparse


def run_command(cmd, cwd=None):
    """
    셸 명령을 실행하고 출력 결과를 스트리밍합니다.
    cmd: 명령어 리스트
    cwd: 명령을 실행할 디렉터리
    """
    print(f"Running: {' '.join(cmd)}")
    # subprocess.run으로 명령 실행
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        # 오류 출력 후 종료
        print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
        sys.exit(result.returncode)


def ensure_mapping(lxc_path, code_path, sbom_path, risk_db, enriched_db, threat_map):
    """
    LXC-Threat-API-Mapping 파이프라인의 주요 단계들을 순서대로 실행하거나
    이미 결과물이 있으면 스킵합니다.
    lxc_path: LXC-Threat-API-Mapping 리포지토리 경로
    code_path: 스캔할 코드베이스 경로
    sbom_path: SBOM JSON 파일 경로
    risk_db: 생성될 risk_db.json 파일 경로
    enriched_db: 생성될 enriched risk DB 경로
    threat_map: 생성될 threat_map.json 파일 경로
    """
    # 1단계: SBOM → risk_db.json 생성
    if not os.path.exists(risk_db):
        run_command([
            sys.executable, 'nvd_api_extractor.py',
            '--sbom', sbom_path,
            '--out', risk_db
        ], cwd=lxc_path)
    else:
        print(f"Found existing risk DB: {risk_db}")

    # 2단계: (선택) LLM을 통한 API 보강
    if not os.path.exists(enriched_db):
        run_command([
            sys.executable, 'llm_api_enricher.py',
            risk_db,
            '--out', enriched_db
        ], cwd=lxc_path)
    else:
        print(f"Found existing enriched DB: {enriched_db}")

    # 3단계: threat_map.json 생성 (코드 스캔)
    if not os.path.exists(threat_map):
        run_command([
            sys.executable, 'threat_api_mapper.py',
            '--code', code_path,
            '--risk', enriched_db,
            '--out', threat_map
        ], cwd=lxc_path)
    else:
        print(f"Found existing threat map: {threat_map}")


def visualize_calls(ast_path, threat_map, output_dir):
    """
    threat_map.json 결과를 읽어서 각 위험 API 호출 위치를
    python-ast-visualizer로 시각화하고 PNG로 저장합니다.
    ast_path: python-ast-visualizer 리포지토리 경로
    threat_map: threat_map.json 파일 경로
    output_dir: 시각화 이미지 저장 디렉터리
    """
    # 출력 디렉터리 없으면 생성
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # threat_map.json 로드
    with open(threat_map, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 각 엔트리에 대해 astvisualizer 실행
    for entry in data:
        file_path = entry.get('file')  # 코드 파일 경로
        api_pattern = entry.get('api')  # 매칭된 API 패턴 (정규식)
        if not file_path or not api_pattern:
            continue

        # 실제 파일 절대 경로 계산
        abs_file = os.path.join(entry.get('code_root', ''), file_path)
        basename = os.path.splitext(os.path.basename(file_path))[0]
        # 간단한 패턴 처리 (^[...]$ 제거)
        target_name = api_pattern.strip('^$\\')
        out_png = os.path.join(output_dir, f"{basename}_{target_name}.png")

        # python-ast-visualizer 명령어 구성
        cmd = [
            sys.executable, os.path.join(ast_path, 'astvisualizer.py'),
            '-f', abs_file,
            '--target', target_name,
            '-o', out_png
        ]
        run_command(cmd)
        print(f"Generated diagram: {out_png}")


def main():
    # argparse로 CLI 인자 처리
    parser = argparse.ArgumentParser(
        description='LXC-Threat-API-Mapping과 python-ast-visualizer를 자동 연결하는 스크립트'
    )
    parser.add_argument('--lxc-repo', required=True, help='LXC-Threat-API-Mapping 리포지토리 경로')
    parser.add_argument('--ast-repo', required=True, help='python-ast-visualizer 리포지토리 경로')
    parser.add_argument('--code', required=True, help='스캔할 코드베이스 경로')
    parser.add_argument('--sbom', required=True, help='SBOM JSON 파일 경로')
    parser.add_argument('--output', default='output', help='시각화 결과물 저장 경로')

    args = parser.parse_args()

    lxc = args.lxc_repo
    astviz = args.ast_repo
    code = args.code
    sbom = args.sbom
    out_dir = args.output

    # 중간 결과물 파일 경로 정의
    risk_db = os.path.join(lxc, 'risk_db.json')
    enriched = os.path.join(lxc, 'risk_db_llm.json')
    threat_map = os.path.join(lxc, 'threat_map.json')

    # 1) LXC-Threat-API-Mapping 파이프라인 실행
    ensure_mapping(lxc, code, sbom, risk_db, enriched, threat_map)

    # 2) 생성된 threat_map.json 기반 AST 시각화
    visualize_calls(astviz, threat_map, out_dir)

    print("워크플로우 완료. threat_map.json과 시각화 이미지를 확인하세요.")


if __name__ == '__main__':
    main()
