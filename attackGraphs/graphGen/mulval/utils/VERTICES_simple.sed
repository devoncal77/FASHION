s/^\([0-9]*\),"\([^"]*\)","AND",\([0-9]*\)$/\t\1 \[label="\1:\3",shape=AND\];/
s/^\([0-9]*\),"\([^"]*\)","AND",\([0-9]*.[0-9]*\)$/\t\1 \[label="\1:\3",shape=AND\];/
s/^\([0-9]*\),"\([^"]*\)","OR",\([0-9]*\)$/\t\1 \[label="\1:\3",shape=OR\];/
s/^\([0-9]*\),"\([^"]*\)","OR",\([0-9]*.[0-9]*\)$/\t\1 \[label="\1:\3",shape=OR\];/
s/^\([0-9]*\),"\([^"]*\)","\([^"]*\)",\([0-9]*\)$/\t\1 \[label="\1",shape=\3\];/
s/^\([0-9]*\),"\([^"]*\)","\([^"]*\)",\([0-9]*.[0-9]*\)$/\t\1 \[label="\1",shape=\3\];/
s/^\([0-9]*\),"\([^"]*\)","\([^"]*\)"$/\t\1 \[label="\1",shape=\3\];/
s/OR/diamond/
s/AND/ellipse/
s/LEAF/box/