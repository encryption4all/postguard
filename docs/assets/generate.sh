set -e

plantuml decrypt.uml
dot -Tsvg projects.dot -oprojects.svg
inkscape -z projects.svg -e projects.png
xelatex abs-encrypt.tex 
gs -sDEVICE=pngalpha -sOutputFile=abs-encrypt.png -dNOPAUSE -dNOPROMPT -dBATCH -r144 abs-encrypt.pdf 
xelatex abs-decrypt.tex 
gs -sDEVICE=pngalpha -sOutputFile=abs-decrypt.png -dNOPAUSE -dNOPROMPT -dBATCH -r144 abs-decrypt.pdf 