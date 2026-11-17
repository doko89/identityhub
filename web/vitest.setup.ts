// jsdom has no ResizeObserver; Radix primitives (Select, DropdownMenu)
// construct one at mount, so tests install the no-op shape. Assigned
// directly (not via vi.stubGlobal) so per-file unstubAllGlobals calls
// cannot remove it.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
