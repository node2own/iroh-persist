#!/bin/false

PROJECT_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" || true ; pwd)"
PROJECT_DIR="$(dirname "${PROJECT_BIN}")"
PROJECT_NAME="$(basename "${PROJECT_DIR}")"
WORKSPACE="$(dirname "${PROJECT_DIR}")"
export PROJECT_BIN PROJECT_DIR PROJECT_NAME WORKSPACE

function remove-dirs() {
  local LIST="$1"
  shift
  echo "${LIST}" | tr ':' '\012' \
    | while read -r D
      do
        I="true"
        for R in "$@"
        do
          if [[ ".${D}" = ".${R}" ]]
          then
            I="false"
          fi
          if "${I}"
          then
            echo "${D}"
          fi
        done
      done \
    | tr '\012' : \
    | sed -e 's/:$//'
}

function find-bin-dirs() {
  local TOP="$1"
  local DEPTH="$2"
  find "${TOP}" -maxdepth "${DEPTH}" \( -type d -name node_modules -prune -type f \) -o -type d -name bin \
    | sed -e 's:/bin$:/!:' \
    | sort \
    | sed -e 's@/!$@/bin@'
}

M='3'

while read -r B
do
  PATH="$(remove-dirs "${PATH}" "${B}")"
  ## echo "Removed [${B}] from [${PATH}]"
done < <(find-bin-dirs "${WORKSPACE}" "$(( M + 1 ))")

PATH="$(find-bin-dirs "${PROJECT_DIR}" "${M}" | tr '\012' ':' | sed -e 's/:$//'):${PATH}"

if [ -f "${PROJECT_BIN}/bashrc.sh" ]
then
  source "${PROJECT_BIN}/bashrc.sh"
fi

function tput_color() {
    echo -n "\\[$(tput setaf "$1")\\]"
}

GREEN="$(tput_color 2)"
YELLOW="$(tput_color 3)"
BLUE="$(tput_color 4)"
CYAN="$(tput_color 6)"
STANDARD="\\[$(tput sgr0)\\]"

PS1="${BLUE}\u@${HOSTNAME} ${GREEN}${PROJECT_NAME}${STANDARD}:${CYAN}\W ${YELLOW}\$${STANDARD} "
echo -n -e "\033]0;${PROJECT_NAME}\a"
