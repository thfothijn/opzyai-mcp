import { describe, it, expect } from 'vitest';
import { scoreFor, type LocalFinding } from './types';

const finding = (category: LocalFinding['category'], severity: LocalFinding['severity']): LocalFinding => ({
  category, signature: 's', title: 't', severity, location: 'l', evidence: 'e', remediation: 'r',
});

describe('scoreFor', () => {
  it('subtracts severity weights from 100 for the dangerous categories', () => {
    expect(scoreFor([])).toBe(100);
    expect(scoreFor([finding('secret', 'critical')])).toBe(55);
    expect(scoreFor([finding('secret', 'critical'), finding('secret', 'critical'), finding('secret', 'high')])).toBe(0); // clamped
  });

  it('caps the dependency penalty so a pile of CVEs cannot alone hit 0', () => {
    // 20 medium deps = 160 raw penalty, but the dependency group is capped at 35 → score 65
    const many = Array.from({ length: 20 }, () => finding('dependency', 'medium'));
    expect(scoreFor(many)).toBe(65);
  });

  it('still tanks the score for a leaked secret on top of capped deps', () => {
    const deps = Array.from({ length: 20 }, () => finding('dependency', 'medium'));
    // critical secret (-45, uncapped) + capped deps (-35) = 20
    expect(scoreFor([finding('secret', 'critical'), ...deps])).toBe(20);
  });
});
