from datetime import datetime
from typing import List, Optional
import hashlib
import time
import logging
from pathlib import Path

from pydantic import BaseModel
from tqdm import tqdm


def get_logger(
    name: str,
    filename: Optional[str | Path] = None,
    verbose: bool =True,
    datefmt: str ="%d.%m.%Y %H:%M:%S",
    log_level: int = logging.DEBUG,
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

    if log_level:
        logger.setLevel(log_level)
    return logger

logger = get_logger("block_chain")

class Block(BaseModel):
    timestamp: datetime
    data: str
    nonce: int
    current_hash: str
    previous_hash: Optional[str] = None

    def get_hash(self) -> str:
        content = f'{self.previous_hash}{self.timestamp}{self.data}{self.nonce}'
        encoded = content.encode('utf-8')
        return hashlib.sha256(encoded).hexdigest()

    def mine(self, difficulty: int) -> None:
        prefix = '0' * difficulty
        with tqdm(desc=f"Mine[difficulty: {difficulty}]") as pbar:
            while True:
                self.current_hash = self.get_hash()
                if self.current_hash.startswith(prefix):
                    break
                self.nonce += 1
                pbar.update(1)


class BlockChain(BaseModel):
    difficulty: int
    time_difficulty: int  # ms
    blockchain: List[Block] = []

    def get_last_block(self) -> Optional[Block]:
        return self.blockchain[-1] if self.blockchain else None

    def add_new_block(self, data: str) -> Block:
        previous_block = self.get_last_block()
        previous_hash = previous_block.current_hash if previous_block else None

        new_block = Block(
            timestamp=datetime.now(),
            data=data,
            nonce=0,
            current_hash='',
            previous_hash=previous_hash,
        )

        start = time.time()
        new_block.mine(self.difficulty)
        end = time.time()

        elapsed_ms = (end - start) * 1000
        if elapsed_ms < self.time_difficulty:
            delay = (self.time_difficulty - elapsed_ms) / 1000
            time.sleep(delay)

        self.blockchain.append(new_block)
        logger.info(f'Block mined: {new_block.current_hash}')
        return new_block

    def check_chain(self) -> bool:
        for i in range(1, len(self.blockchain)):
            current = self.blockchain[i]
            previous = self.blockchain[i - 1]

            if current.previous_hash != previous.current_hash:
                logger.error(f'Hash mismatch at block {i}')
                return False

            if current.get_hash() != current.current_hash:
                logger.error(f'Invalid hash at block {i}')
                return False

        logger.info('Blockchain is valid')
        return True


def test_blockchain(difficulty: int, time_difficulty: int, log_file: str) -> None:
    blockchain = BlockChain(difficulty=difficulty, time_difficulty=time_difficulty)

    genesis_block = Block(
        timestamp=datetime.now(),
        data='Genesis Block; Miner gets 100 BTC',
        nonce=0,
        current_hash='',
        previous_hash=None,
    )
    genesis_block.mine(blockchain.difficulty)
    blockchain.blockchain.append(genesis_block)

    for i in range(1, 4):
        blockchain.add_new_block(f'Data {i}; Miner gets {50//i} BTC')

    assert blockchain.check_chain()

    with open(log_file, 'w') as f:
        for block in blockchain.blockchain:
            f.write(
                f"Data: '{block.data}'\n"
                f"Timestamp: {int(block.timestamp.timestamp())}\n"
                f"Nonce: {block.nonce}\n"
                f"Hash: '{block.current_hash}'\n"
                f"PrevHash: '{block.previous_hash}'\n\n"
            )


if __name__ == '__main__':
    params = {
        'difficulty': 4,
        'time_difficulty': 1000,
        'log_file': 'logs/blockchain.txt'
    }
    test_blockchain(**params)
