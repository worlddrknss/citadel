// Display density (comfortable / compact), persisted like the theme and
// applied as data-density on <html>, where styles.css swaps --row-h,
// --ctl-h and --pad-page.

export type Density = 'comfortable' | 'compact';
const KEY = 'citadel-density';

function read(): Density {
  try {
    return localStorage.getItem(KEY) === 'compact' ? 'compact' : 'comfortable';
  } catch {
    return 'comfortable';
  }
}

function apply(d: Density) {
  if (typeof document === 'undefined') return;
  if (d === 'compact') document.documentElement.setAttribute('data-density', 'compact');
  else document.documentElement.removeAttribute('data-density');
}

function createDensity() {
  const initial: Density = typeof localStorage === 'undefined' ? 'comfortable' : read();
  apply(initial);
  let value = $state<Density>(initial);
  return {
    get value() {
      return value;
    },
    set(d: Density) {
      value = d;
      apply(d);
      try {
        if (d === 'compact') localStorage.setItem(KEY, d);
        else localStorage.removeItem(KEY);
      } catch {
        /* not persisted; fine */
      }
    }
  };
}

export const density = createDensity();
