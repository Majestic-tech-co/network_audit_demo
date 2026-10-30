import { create } from "zustand";

export interface ScanProgress {
  scanId: string;
  percent: number;
  message: string;
  status: "running" | "complete" | "failed";
  hostsFound?: number;
  findingsCount?: number;
  startedAt: Date;
}

interface ScanProgressState {
  activeScans: Record<string, ScanProgress>;
  setScanProgress: (scanId: string, update: Partial<ScanProgress>) => void;
  completeScan: (scanId: string, data: { hostsFound: number; findingsCount: number }) => void;
  failScan: (scanId: string, message: string) => void;
  startScan: (scanId: string, message: string) => void;
  clearScan: (scanId: string) => void;
}

export const useScanProgressStore = create<ScanProgressState>((set) => ({
  activeScans: {},

  startScan: (scanId, message) =>
    set((state) => ({
      activeScans: {
        ...state.activeScans,
        [scanId]: {
          scanId,
          percent: 5,
          message,
          status: "running",
          startedAt: new Date(),
        },
      },
    })),

  setScanProgress: (scanId, update) =>
    set((state) => ({
      activeScans: {
        ...state.activeScans,
        [scanId]: { ...state.activeScans[scanId], ...update },
      },
    })),

  completeScan: (scanId, { hostsFound, findingsCount }) =>
    set((state) => ({
      activeScans: {
        ...state.activeScans,
        [scanId]: {
          ...state.activeScans[scanId],
          percent: 100,
          status: "complete",
          hostsFound,
          findingsCount,
          message: `Complete — ${hostsFound} hosts, ${findingsCount} findings`,
        },
      },
    })),

  failScan: (scanId, message) =>
    set((state) => ({
      activeScans: {
        ...state.activeScans,
        [scanId]: {
          ...state.activeScans[scanId],
          percent: 100,
          status: "failed",
          message,
        },
      },
    })),

  clearScan: (scanId) =>
    set((state) => {
      const next = { ...state.activeScans };
      delete next[scanId];
      return { activeScans: next };
    }),
}));
