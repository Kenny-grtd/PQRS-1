from pathlib import Path
import tokenize, io
path = Path('autenticacion/autenticacion.py')
text = path.read_text(encoding='utf-8')
reader = io.BytesIO(text.encode('utf-8')).readline
paren = 0
line_paren = {}
for tok in tokenize.tokenize(reader):
    if tok.type == tokenize.OP:
        if tok.string == '(':
            paren += 1
        elif tok.string == ')':
            paren -= 1
    if tok.type in (tokenize.NEWLINE, tokenize.NL):
        line_paren[tok.start[0]] = paren
for i in range(5000, 5780):
    if line_paren.get(i) is not None:
        print(f'{i}: {line_paren[i]}')
print('final paren', paren)
