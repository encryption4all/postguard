set -e

pushd assets
./generate.sh
popd

pandoc -f markdown -t html5 --highlight-style=haddock --css $HOME/sarif/markdown-css/github.css --self-contained -o design.html design.md