
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import uuid
import bcrypt
import pandas as pd
import io
from fpdf import FPDF
import os
import uvicorn

app = FastAPI(title="LexMind API")

@app.get("/")
def root():
    return {"mensagem": "Bem-vindo à API do LexMind — automação inteligente para escritórios de advocacia. Explore a documentação em /docs."}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Simulated in-memory database
usuarios_db = {}
peticoes_db = []

class Usuario(BaseModel):
    id: str
    nome: str
    email: str
    senha_hash: str
    tipo_usuario: str
    criado_em: datetime

class Peticao(BaseModel):
    id: str
    titulo: str
    tipo: str
    advogado_id: str
    cliente: str
    processo: str
    status: str
    data_protocolo: datetime
    prazo: datetime
    arquivo_url: Optional[str] = None
    resumo: Optional[str] = None
    criado_em: datetime

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = next((u for u in usuarios_db.values() if u.email == form_data.username), None)
    if not user or not verify_password(form_data.password, user.senha_hash):
        raise HTTPException(status_code=400, detail="Credenciais inválidas")
    return {"access_token": user.id, "token_type": "bearer"}

@app.get("/usuarios/me")
def get_me(token: str = Depends(oauth2_scheme)):
    user = usuarios_db.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não autenticado")
    return user

@app.post("/upload/peticao")
def upload_peticao(file: UploadFile = File(...)):
    if file.filename.endswith('.xlsx') or file.filename.endswith('.csv'):
        contents = file.file.read()
        df = pd.read_excel(io.BytesIO(contents)) if file.filename.endswith('.xlsx') else pd.read_csv(io.StringIO(contents.decode('utf-8')))
        created_peticoes = []
        for _, row in df.iterrows():
            peticao = Peticao(
                id=str(uuid.uuid4()),
                titulo=row.get("titulo", "Petição Sem Título"),
                tipo=row.get("tipo", ""),
                advogado_id=row.get("advogado_id", ""),
                cliente=row.get("cliente", ""),
                processo=row.get("processo", ""),
                status=row.get("status", ""),
                data_protocolo=pd.to_datetime(row.get("data_protocolo", datetime.now())),
                prazo=pd.to_datetime(row.get("prazo", datetime.now() + timedelta(days=7))),
                arquivo_url=None,
                criado_em=datetime.now()
            )
            peticoes_db.append(peticao)
            created_peticoes.append(peticao.id)
        return {"mensagem": "Planilha processada com sucesso", "peticoes_ids": created_peticoes}
    else:
        raise HTTPException(status_code=400, detail="Formato de arquivo não suportado")

@app.get("/peticoes", response_model=List[Peticao])
def listar_peticoes(tipo: Optional[str] = None, advogado_id: Optional[str] = None):
    result = peticoes_db
    if tipo:
        result = [p for p in result if p.tipo == tipo]
    if advogado_id:
        result = [p for p in result if p.advogado_id == advogado_id]
    return result

@app.get("/relatorios/excel")
def exportar_excel():
    df = pd.DataFrame([p.dict() for p in peticoes_db])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Peticoes')
    output.seek(0)
    return Response(content=output.read(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=relatorio_peticoes.xlsx"})

@app.get("/relatorios/pdf")
def exportar_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Relatório de Petições", ln=True, align='C')
    for p in peticoes_db:
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Título: {p.titulo} | Cliente: {p.cliente} | Tipo: {p.tipo}", ln=True)
    output = io.BytesIO()
    pdf.output(output)
    output.seek(0)
    return Response(content=output.read(), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=relatorio_peticoes.pdf"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
