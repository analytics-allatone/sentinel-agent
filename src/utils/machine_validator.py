import asyncssh
import os
from pathlib import Path

async def validate_ssh(host:str , username:str , password:str|None , private_key:str|None ,port:int = 22, auth_type:str = "password"):
    try:
        if auth_type == "key":
            if private_key:
                # This parses the string content of the private key
                private_key = asyncssh.import_private_key(private_key)
            else:
                return False
            async with asyncssh.connect(
                host,
                port=port,
                username=username,
                client_keys=[private_key],
                known_hosts=None
            ):
                return True
        elif auth_type == "password":
            async with asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                known_hosts=None
            ):
                return True
        else:
            return False


    except Exception as e:
        return False
    



async def run_ssh_command(host: str, username: str, command: str, password: str|None = None, private_key: str|None = None, port: int = 22, auth_type: str = "password"):
    try:
        # Prepare Auth
        connect_params = {
            "host": host,
            "port": port,
            "username": username,
            "known_hosts": None
        }

        if auth_type == "key" and private_key:
            connect_params["client_keys"] = [asyncssh.import_private_key(private_key)]
        elif auth_type == "password":
            connect_params["password"] = password

        # Connect and Execute
        async with asyncssh.connect(**connect_params) as conn:
            result = await conn.run(command, check=True)
            
            # .stdout contains the successful output
            # .stderr contains any error messages
            if result.stdout:
                return f"SUCCESS:\n{result.stdout}"
            else:
                return f"EMPTY RESULT / ERRORS:\n{result.stderr}"

    except Exception as e:
        return f"CONNECTION FAILED: {str(e)}"




import asyncssh
import os


async def upload_folder_with_identity(
    host: str,
    username: str,
    local_path: str,
    machine_id: int,
    kafka_broker: str,
    kafka_topic: str,
    remote_path: str,
    password: str | None = None,
    private_key: str | None = None,
    port: int = 22,
    auth_type: str = "password"
):

    # ─────────────────────────────
    # 1. LOCAL VALIDATION
    # ─────────────────────────────
    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local path does not exist: {local_path}")

    if not os.path.isdir(local_path):
        raise NotADirectoryError(f"Not a directory: {local_path}")

    ALLOWED_EXTENSIONS = {".py", ".txt"}

    all_files = []
    for root, dirs, files in os.walk(local_path):
        dirs[:] = [d for d in dirs if d not in {"venv", "__pycache__", ".git"}]

        for file in files:
            if os.path.splitext(file)[1] not in ALLOWED_EXTENSIONS:
                continue

            all_files.append(os.path.join(root, file))

    # ─────────────────────────────
    # 2. SSH CONNECT
    # ─────────────────────────────
    connect_params = {
        "host": host,
        "port": port,
        "username": username,
        "known_hosts": None,
    }

    if auth_type == "key" and private_key:
        connect_params["client_keys"] = [
            asyncssh.import_private_key(private_key)
        ]
    else:
        connect_params["password"] = password

    async with asyncssh.connect(**connect_params) as conn:


        sftp = await conn.start_sftp_client()

        # ─────────────────────────────
        # 3. CREATE REMOTE STRUCTURE
        # ─────────────────────────────
        await conn.run(f"mkdir -p {remote_path}")
        await conn.run(f"mkdir -p {remote_path}/config")
        base = Path(local_path)

        all_files = [
            p for p in base.rglob("*")
            if p.is_file()
            and p.suffix in {".py", ".txt"}
            and not any(part in {"venv", "__pycache__", ".git"} for part in p.parts)
        ]

        for file_path in all_files:

            rel_path = file_path.relative_to(base).as_posix()
            remote_file = f"{remote_path.rstrip('/')}/{rel_path}"

            remote_dir = str(Path(remote_file).parent).replace("\\", "/")

            await conn.run(f"mkdir -p {remote_dir}")
            await sftp.put(str(file_path), remote_file)

        # ─────────────────────────────
        # 5. CREATE IDENTITY FILE (FIXED)
        # ─────────────────────────────
        identity_file_content = (
            f"MACHINE_ID = {machine_id}\n"
            f'KAFKA_BROKER = "{kafka_broker}"\n'
            f'KAFKA_TOPIC = "{kafka_topic}"\n'
        )

        identity_path = f"{remote_path}/config/unique_info.py"

        async with sftp.open(identity_path, "w") as f:
            await f.write(identity_file_content)

        return "UPLOAD + IDENTITY CREATED"