import sys

tools = []
for mod in ["matplotlib", "PIL", "graphviz", "cairosvg", "reportlab"]:
    try:
        __import__(mod)
        tools.append(mod + ": YES")
    except ImportError as e:
        tools.append(mod + f": NO ({e})")

print(" | ".join(tools))

