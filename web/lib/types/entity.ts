import type { EntityCategoryKey } from "./investigation";

export type { EntityCategoryKey };

export interface InvestigationAppearance {
  investigation_id: string;
  run_id: string;
  query: string;
  created_at: string | null;
}

export interface EntityNeighbor {
  id: string;
  entity_type: string;
  value: string;
  confidence: number;
  relationship_type: string;
  strength: number;
}

export interface EntityProfile {
  id: string;
  entity_type: string;
  value: string;
  canonical_value: string | null;
  confidence: number;
  context: string | null;
  context_snippet: string | null;
  historical_context: string | null;
  first_seen: string | null;
  last_seen: string | null;
  investigation_id: string | null;
  created_at: string | null;
  source_url: string | null;
  extraction_method: "regex" | "NER" | "LLM" | null;
  is_seed: boolean;
  appearances: InvestigationAppearance[];
  appearance_count: number;
}

export interface EntityRelatedResponse {
  entity: {
    id: string;
    entity_type: string;
    value: string;
    confidence: number;
  };
  neighbors: EntityNeighbor[];
}
