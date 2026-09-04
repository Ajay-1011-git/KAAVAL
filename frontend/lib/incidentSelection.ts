"use client";

import {
  createContext,
  createElement,
  type ReactNode,
  useContext,
  useMemo,
  useState,
} from "react";

export interface SelectedIncident {
  incident_id: string;
  event_ids: string[];
}

interface IncidentSelectionState {
  selectedIncident: SelectedIncident | null;
  setSelectedIncident: (incident: SelectedIncident | null) => void;
}

const IncidentSelectionContext =
  createContext<IncidentSelectionState | null>(null);

export function IncidentSelectionProvider({ children }: { children: ReactNode }) {
  const [selectedIncident, setSelectedIncident] =
    useState<SelectedIncident | null>(null);
  const value = useMemo(
    () => ({ selectedIncident, setSelectedIncident }),
    [selectedIncident],
  );

  return createElement(
    IncidentSelectionContext.Provider,
    { value },
    children,
  );
}

export function useIncidentSelection(): IncidentSelectionState {
  const state = useContext(IncidentSelectionContext);
  if (!state) {
    throw new Error(
      "useIncidentSelection must be used within an IncidentSelectionProvider.",
    );
  }
  return state;
}
