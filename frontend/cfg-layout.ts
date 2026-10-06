export interface CfgLayoutBlock {
    address: string;
    edges: { to: string; type: string }[];
}

export interface CfgLayoutPosition {
    x: number;
    y: number;
    rank: number;
}

/**
 * Produces a stable, top-down layout without treating back edges as a new rank.
 * That keeps loops readable while still placing the normal flow below its source.
 */
export function layoutCfg(blocks: CfgLayoutBlock[]): Map<string, CfgLayoutPosition> {
    const byAddress = new Map(blocks.map(block => [block.address, block]));
    const rank = new Map<string, number>();
    const seen = new Set<string>();
    const queue: string[] = [];
    if (blocks[0]) {
        rank.set(blocks[0].address, 0);
        seen.add(blocks[0].address);
        queue.push(blocks[0].address);
    }
    for (let cursor = 0; cursor < queue.length; cursor++) {
        const source = queue[cursor];
        const sourceRank = rank.get(source) || 0;
        for (const edge of byAddress.get(source)?.edges || []) {
            if (!byAddress.has(edge.to) || seen.has(edge.to)) continue;
            seen.add(edge.to);
            rank.set(edge.to, sourceRank + 1);
            queue.push(edge.to);
        }
    }
    let detachedRank = Math.max(0, ...rank.values()) + 1;
    for (const block of blocks) {
        if (!rank.has(block.address)) rank.set(block.address, detachedRank++);
    }
    const layers = new Map<number, string[]>();
    for (const block of blocks) {
        const level = rank.get(block.address)!;
        const layer = layers.get(level) || [];
        layer.push(block.address);
        layers.set(level, layer);
    }
    const result = new Map<string, CfgLayoutPosition>();
    for (const [level, layer] of layers) {
        layer.forEach((address, index) => result.set(address, {
            x: (index - (layer.length - 1) / 2) * 9,
            y: -level * 5.4,
            rank: level,
        }));
    }
    return result;
}
