#!/usr/bin/env bash

if [ -z "$1" ]; then
    echo "[!] 사용법: $0 <Ghidra 설치 경로>"
    echo "예: $0 \$HOME/tools/ghidra_11.4.2_PUBLIC"
    exit 1
fi

GHIDRA_PATH="$1"

# 경로 확장 (~ 처리)
GHIDRA_PATH="${GHIDRA_PATH/#\~/$HOME}"

echo "[*] 입력된 GHIDRA_PATH: $GHIDRA_PATH"

if [ -f "$HOME/.zshrc" ]; then
    TARGET_RC="$HOME/.zshrc"
    SHELL_TYPE="zsh"
elif [ -f "$HOME/.bashrc" ]; then
    TARGET_RC="$HOME/.bashrc"
    SHELL_TYPE="bash"
else
    TARGET_RC="$HOME/.bashrc"
    SHELL_TYPE="bash"
    touch "$TARGET_RC"
    echo "[*] .zshrc/.bashrc 모두 없어 .bashrc 를 새로 생성합니다."
fi

echo "[*] 환경설정 파일: $TARGET_RC"

if [ ! -d "$GHIDRA_PATH" ]; then
    echo "[!] 경고: Ghidra 디렉토리가 존재하지 않습니다: $GHIDRA_PATH"
    echo "[!] 설치 후 다시 실행해주세요."
    exit 1
fi

if grep -q "GHIDRA_HOME=\"$GHIDRA_PATH\"" "$TARGET_RC"; then
    echo "[=] 이미 $TARGET_RC 에 동일한 Ghidra 설정이 존재합니다. 추가하지 않습니다."
else
    echo "[+] $TARGET_RC 에 Ghidra 설정을 추가합니다."
    {
        echo ""
        echo "# ghidra config"
        echo "export GHIDRA_HOME=\"$GHIDRA_PATH\""
        echo "export PATH=\"\$GHIDRA_HOME/support:\$PATH\""
        echo "alias ghidra=\"\$GHIDRA_HOME/ghidraRun\""
    } >> "$TARGET_RC"
fi

if [ "$SHELL_TYPE" = "zsh" ] && [ -n "$ZSH_VERSION" ]; then
    source "$TARGET_RC"
    echo "[+] zsh 환경에서 설정 즉시 적용 완료!"
elif [ "$SHELL_TYPE" = "bash" ] && [ -n "$BASH_VERSION" ]; then
    source "$TARGET_RC"
    echo "[+] bash 환경에서 설정 즉시 적용 완료!"
else
    echo "[*] 현재 셸에서는 즉시 적용되지 않습니다. 다음 로그인 후 적용됩니다."
fi

echo "[+] Ghidra 환경 구성 완료! ghidra 명령어 사용 가능."
