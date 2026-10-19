"""
Project Unit42-FirmwareX — Entropy Analyzer
Calculates Shannon entropy to identify compressed filesystems, encrypted blocks, and uncompressed code.
"""

import math
from typing import List, Dict, Any, Tuple

class EntropyAnalyzer:
    """Computes Shannon entropy across byte blocks (0.0 - 8.0 bits/byte)"""

    @staticmethod
    def calculate_block_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        
        freq = [0] * 256
        for b in data:
            freq[b] += 1
            
        data_len = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)
                
        return round(entropy, 4)

    @classmethod
    def analyze(cls, data: bytes, block_size: int = 1024, max_points: int = 100) -> Dict[str, Any]:
        """Calculates entropy curve downsampled to max_points for reporting & graphing"""
        if not data:
            return {
                "mean_entropy": 0.0,
                "max_entropy": 0.0,
                "min_entropy": 0.0,
                "data_points": []
            }

        total_len = len(data)
        # Determine step size to maintain <= max_points
        step = max(block_size, total_len // max_points)
        
        points: List[Dict[str, Any]] = []
        entropies: List[float] = []

        for offset in range(0, total_len, step):
            chunk = data[offset : min(offset + block_size, total_len)]
            e = cls.calculate_block_entropy(chunk)
            entropies.append(e)
            points.append({
                "offset": offset,
                "offset_hex": f"0x{offset:08x}",
                "entropy": e
            })

        mean_val = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
        max_val = max(entropies) if entropies else 0.0
        min_val = min(entropies) if entropies else 0.0

        return {
            "mean_entropy": mean_val,
            "max_entropy": max_val,
            "min_entropy": min_val,
            "data_points": points
        }
