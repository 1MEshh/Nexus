#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {
  ShadowGraph,
  calculateRemediationChokepoints,
  findShadowAdmins,
  findShortestAttackPaths,
} from './graph-engine.js';
import {
  generateCypherExport,
  generateHtmlReport,
  generateSarifReport,
  renderAsciiReport,
} from './exporters.js';
import type { PathRoutingMode } from './schema.js';

export interface CliOptions {
  inputPath: string;
  sourceId?: string;
  mode: PathRoutingMode;
  topChokepoints: number;
  htmlOut?: string;
  cypherOut?: string;
  sarifOut?: string;
  jsonOut?: string;
  help: boolean;
}

export function parseCliArgs(argv: readonly string[]): CliOptions {
  const options: CliOptions = {
    inputPath: path.join('samples', 'ad-hybrid-enterprise.json'),
    mode: 'stealth',
    topChokepoints: 10,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '-i':
      case '--input': {
        const val = argv[++i];
        if (!val) {
          throw new Error('Missing value for --input');
        }
        options.inputPath = val;
        break;
      }
      case '-s':
      case '--source': {
        const val = argv[++i];
        if (!val) {
          throw new Error('Missing value for --source');
        }
        options.sourceId = val;
        break;
      }
      case '-m':
      case '--mode': {
        const val = argv[++i];
        if (val !== 'stealth' && val !== 'hops' && val !== 'hybrid') {
          throw new Error(`Invalid routing mode "${String(val)}". Expected: stealth | hops | hybrid`);
        }
        options.mode = val;
        break;
      }
      case '-t':
      case '--top-chokepoints': {
        const val = Number(argv[++i]);
        if (!Number.isInteger(val) || val < 1 || val > 500) {
          throw new Error('Invalid --top-chokepoints value. Expected integer in [1..500]');
        }
        options.topChokepoints = val;
        break;
      }
      case '--html-out': {
        const val = argv[++i];
        if (!val) {
          throw new Error('Missing value for --html-out');
        }
        options.htmlOut = val;
        break;
      }
      case '--cypher-out': {
        const val = argv[++i];
        if (!val) {
          throw new Error('Missing value for --cypher-out');
        }
        options.cypherOut = val;
        break;
      }
      case '--sarif-out': {
        const val = argv[++i];
        if (!val) {
          throw new Error('Missing value for --sarif-out');
        }
        options.sarifOut = val;
        break;
      }
      case '--json-out': {
        const val = argv[++i];
        if (!val) {
          throw new Error('Missing value for --json-out');
        }
        options.jsonOut = val;
        break;
      }
      default:
        throw new Error(`Unknown CLI argument: ${arg}`);
    }
  }

  return options;
}

export function getCliHelpText(): string {
  return [
    'SHADOW-GRAPH // Multi-Domain Identity Attack Path & Chokepoint Engine',
    '',
    'Usage:',
    '  shadow-graph [options]',
    '',
    'Options:',
    '  -i, --input <file>            Path to identity graph JSON (default: samples/ad-hybrid-enterprise.json)',
    '  -s, --source <nodeId>         Evaluate shortest paths from a specific principal ID',
    '  -m, --mode <mode>             Dijkstra routing mode: stealth | hops | hybrid (default: stealth)',
    '  -t, --top-chokepoints <num>   Number of remediation chokepoints to rank (default: 10)',
    '      --html-out <file>         Write standalone HTML/SVG interactive report',
    '      --cypher-out <file>       Write Neo4j Cypher import script',
    '      --sarif-out <file>        Write SARIF v2.1.0 static analysis report',
    '      --json-out <file>         Write structured JSON analysis output',
    '  -h, --help                    Display this help message',
  ].join('\n');
}

export function runCli(argv: readonly string[]): number {
  let options: CliOptions;
  try {
    options = parseCliArgs(argv);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${message}\n\n${getCliHelpText()}\n`);
    return 1;
  }

  if (options.help) {
    process.stdout.write(`${getCliHelpText()}\n`);
    return 0;
  }

  try {
    const resolvedInput = path.resolve(options.inputPath);
    const rawContent = fs.readFileSync(resolvedInput, 'utf8');
    const parsedJson: unknown = JSON.parse(rawContent);
    const graph = ShadowGraph.fromDocument(parsedJson);

    const shadowAdmins = findShadowAdmins(graph, options.mode);
    const chokepoints = calculateRemediationChokepoints(graph, options.topChokepoints, options.mode);

    let attackPaths;
    if (options.sourceId) {
      attackPaths = findShortestAttackPaths(graph, options.sourceId, undefined, options.mode);
    } else {
      const compromised = graph.getCompromisedNodes();
      if (compromised.length > 0) {
        attackPaths = compromised.flatMap((c) =>
          findShortestAttackPaths(graph, c.id, undefined, options.mode)
        );
        attackPaths.sort((a, b) => a.totalWeight - b.totalWeight);
      } else {
        attackPaths = shadowAdmins.map((sa) => sa.shortestPathToTierZero);
      }
    }

    const asciiReport = renderAsciiReport(graph, attackPaths, shadowAdmins, chokepoints);
    process.stdout.write(`${asciiReport}\n`);

    if (options.htmlOut) {
      const htmlPath = path.resolve(options.htmlOut);
      const htmlContent = generateHtmlReport(graph, attackPaths, shadowAdmins, chokepoints);
      fs.writeFileSync(htmlPath, htmlContent, 'utf8');
      process.stdout.write(`HTML report written to: ${options.htmlOut}\n`);
    }

    if (options.cypherOut) {
      const cypherPath = path.resolve(options.cypherOut);
      const cypherContent = generateCypherExport(graph, shadowAdmins, chokepoints);
      fs.writeFileSync(cypherPath, cypherContent, 'utf8');
      process.stdout.write(`Neo4j Cypher script written to: ${options.cypherOut}\n`);
    }

    if (options.sarifOut) {
      const sarifPath = path.resolve(options.sarifOut);
      const sarifObj = generateSarifReport(graph, shadowAdmins, chokepoints, options.inputPath);
      fs.writeFileSync(sarifPath, JSON.stringify(sarifObj, null, 2), 'utf8');
      process.stdout.write(`SARIF v2.1.0 report written to: ${options.sarifOut}\n`);
    }

    if (options.jsonOut) {
      const jsonPath = path.resolve(options.jsonOut);
      const summary = {
        metadata: graph.metadata,
        mode: options.mode,
        attackPaths,
        shadowAdmins,
        chokepoints,
      };
      fs.writeFileSync(jsonPath, JSON.stringify(summary, null, 2), 'utf8');
      process.stdout.write(`JSON report written to: ${options.jsonOut}\n`);
    }

    return 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Execution failed: ${message}\n`);
    return 1;
  }
}

// Execute when invoked directly via CLI
const isDirectExecution =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('cli.ts'));

if (isDirectExecution) {
  const code = runCli(process.argv.slice(2));
  process.exitCode = code;
}
