from pathlib import Path

from logger import logger

def read_file(file: str | Path) -> bytes:
    file = Path(file)
    with open(file, 'rb') as f:
        content = f.read()
    logger.info(f"Read file: {str(file)}")
    return content

def write_file(file: str | Path, data) -> None:
    file = Path(file)
    with open(file, "wb") as f:
        f.write(data)
    logger.info(f"Wrote file: {str(file)}")
