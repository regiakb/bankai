# Subir Bankai a GitHub y Docker Hub

Usuarios de ejemplo: GitHub **regiakb**, Docker Hub **regiakb7**.

## 1. Subir a GitHub

### Crear el repositorio en GitHub
1. Entra en [github.com](https://github.com) y crea un **nuevo repositorio** (por ejemplo `bankai`).
2. No inicialices con README si ya tienes código local.

### Inicializar Git y subir el código

```bash
cd /home/bankai

# Inicializar repositorio (si aún no existe)
git init

# Añadir todos los archivos (respetando .gitignore)
git add .
git status   # revisar que no se suban db.sqlite3, .env, logs, etc.

# Primer commit
git commit -m "Initial commit: Bankai con Docker"

# Añadir tu repositorio de GitHub
git remote add origin https://github.com/regiakb/bankai.git

# Subir (rama main)
git branch -M main
git push -u origin main
```

Si GitHub te pide autenticación, usa un **Personal Access Token** (Settings → Developer settings → Personal access tokens) en lugar de la contraseña.

---

## 2. Subir la imagen a Docker Hub

### Cuenta en Docker Hub
1. Regístrate en [hub.docker.com](https://hub.docker.com) si no tienes cuenta.
2. Crea un repositorio (por ejemplo `bankai`) en la web o se creará al hacer el primer push.

### Build, tag y push

```bash
cd /home/bankai

# Iniciar sesión en Docker Hub
docker login

# Construir la imagen con el nombre que usará Docker Hub
docker build -t regiakb7/bankai:latest .

# Subir la imagen
docker push regiakb7/bankai:latest
```

### Usar la imagen desde Docker Hub en otro equipo

```bash
docker pull regiakb7/bankai:latest
```

Para usar esa imagen en lugar de construir localmente, en `docker-compose.yml` puedes poner:

```yaml
services:
  bankai:
    image: regiakb7/bankai:latest
    # build: ...  # comenta o elimina la sección build si usas solo la imagen
```

---

## Resumen de comandos

**GitHub:**
```bash
git init && git add . && git commit -m "Initial commit: Bankai con Docker"
git remote add origin https://github.com/regiakb/bankai.git
git branch -M main && git push -u origin main
```

**Docker Hub:**
```bash
docker login
docker build -t regiakb7/bankai:latest .
docker push regiakb7/bankai:latest
```
