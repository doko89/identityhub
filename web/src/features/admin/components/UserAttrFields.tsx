import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/shared/ui/select";
import { Textarea } from "@/shared/ui/textarea";
import type { AttrDef, AttrDrafts } from "../api";

// UserAttrFields edits one user's custom attributes: one editor per def
// (text for string/number, tri-state select for boolean, one-value-per
// line for multi-valued). Clearing an editor clears the key on save.
// Used by the attributes console and the user add/edit sheets alike.
export function UserAttrFields({
  defs,
  drafts,
  onChange,
  idPrefix,
}: {
  defs: AttrDef[];
  drafts: AttrDrafts;
  onChange: (next: AttrDrafts) => void;
  idPrefix: string;
}) {
  if (defs.length === 0) {
    return null;
  }
  const set = (key: string, value: string) => onChange({ ...drafts, [key]: value });
  return (
    <div>
      <p className="mt-1 mb-3 text-sm text-muted-foreground">
        Upstream-mapped keys are overwritten by the next directory sync.
      </p>
      {defs.map((d) => (
        <Field key={d.key} className="mb-3">
          <FieldLabel htmlFor={`${idPrefix}${d.key}`}>
            <span className="font-mono text-[13px]">{d.key}</span>
            <span className="ml-2 font-normal text-muted-foreground">
              {d.type}
              {d.multi ? " · multi" : ""}
            </span>
          </FieldLabel>
          {d.multi ? (
            <Textarea
              id={`${idPrefix}${d.key}`}
              value={drafts[d.key] ?? ""}
              onChange={(e) => set(d.key, e.target.value)}
              placeholder="one value per line"
              rows={3}
            />
          ) : d.type === "boolean" ? (
            <Select
              value={drafts[d.key] === "" || drafts[d.key] === undefined ? "unset" : drafts[d.key]}
              onValueChange={(v) => set(d.key, v === "unset" ? "" : v)}
            >
              <SelectTrigger id={`${idPrefix}${d.key}`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="unset">Unset</SelectItem>
                <SelectItem value="true">true</SelectItem>
                <SelectItem value="false">false</SelectItem>
              </SelectContent>
            </Select>
          ) : (
            <Input
              id={`${idPrefix}${d.key}`}
              value={drafts[d.key] ?? ""}
              onChange={(e) => set(d.key, e.target.value)}
              placeholder={d.type === "number" ? "3" : "value"}
            />
          )}
        </Field>
      ))}
    </div>
  );
}
