#!/usr/bin/env bash

GHIDRA_PATH="$HOME/tools/ghidra_11.4.2_PUBLIC"

echo "[+] Ghidra 환경 변수 설정을 시작합니다."

# .zshrc에 설정 추가
{
  echo ""
  echo "# ghidra config"
  echo "export GHIDRA_HOME=\"$GHIDRA_PATH\""
  echo "export PATH=\"\$GHIDRA_HOME/support:\$PATH\""
  echo "alias ghidra=\"\$GHIDRA_HOME/ghidraRun\""
} >> ~/.zshrc

echo "[+] ~/.zshrc 파일에 Ghidra 환경 변수가 추가되었습니다."

# 변경 사항 적용
# zshrc 존재 시 적용
if [ -f "$HOME/.zshrc" ]; then
    source "$HOME/.zshrc"
    echo "[+] 환경변수 적용 완료!"
else
    echo "[!] ~/.zshrc 파일이 존재하지 않습니다. 직접 적용해주세요."
fi

echo "[+] ghidra 명령어를 사용할 수 있습니다."
