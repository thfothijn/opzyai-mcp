import { scanWorkingTreeSecrets } from './detectors/secrets';
import { scanDotenv } from './detectors/dotenv';
import { scanGitHistory } from './detectors/git-history';
import { scanDependencies } from './detectors/deps';
import { scoreFor, type LocalFinding, type LocalScanReport } from './types';

export async function runSecurityCheck(opts: { root: string; offline?: boolean }): Promise<LocalScanReport> {
  const { root, offline = false } = opts;
  const [secrets, dotenv, history, deps] = await Promise.all([
    scanWorkingTreeSecrets(root).catch(() => [] as LocalFinding[]),
    scanDotenv(root).catch(() => [] as LocalFinding[]),
    scanGitHistory(root).catch(() => [] as LocalFinding[]),
    offline ? Promise.resolve([] as LocalFinding[]) : scanDependencies(root).catch(() => [] as LocalFinding[]),
  ]);
  const findings = [...secrets, ...dotenv, ...history, ...deps];
  return {
    score: scoreFor(findings),
    findings,
    ranBy: { secrets: true, dotenv: true, history: true, deps: offline ? 'offline' : true },
  };
}
