import { render, screen, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import { describe, expect, it } from 'vitest';
import DataTable, { type Column } from './DataTable.svelte';

interface Row {
  name: string;
  size: number;
}

const rows: Row[] = Array.from({ length: 30 }, (_, i) => ({ name: `item-${i + 1}`, size: (i * 7) % 30 }));

const columns: Column<Row>[] = [
  { id: 'name', label: 'Name', sort: (r) => r.name },
  { id: 'size', label: 'Size', sort: (r) => r.size },
  { id: 'note', label: 'Note' }
];

const row = createRawSnippet((r: () => Row) => ({
  render: () => `<td>${r().name}</td>`
}));

function setup(props: Record<string, unknown> = {}) {
  const user = userEvent.setup();
  const result = render(DataTable<Row>, {
    rows,
    columns,
    key: (r: Row) => r.name,
    row,
    caption: 'Items',
    searchable: (r: Row) => r.name,
    pageSize: 10,
    ...props
  });
  return { user, ...result };
}

const bodyNames = () =>
  screen
    .getAllByRole('row')
    .slice(1)
    .map((tr) => tr.querySelector('td:last-child')?.textContent);

describe('DataTable', () => {
  it('shows the first page and a range', () => {
    setup();
    expect(bodyNames()).toHaveLength(10);
    expect(bodyNames()[0]).toBe('item-1');
    expect(screen.getByText('1–10 of 30')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
  });

  it('pages forward and back', async () => {
    const { user } = setup();
    const next = screen.getByRole('button', { name: 'Next page' });
    await user.click(next);
    expect(screen.getByText('11–20 of 30')).toBeInTheDocument();
    await user.click(next);
    expect(screen.getByText('21–30 of 30')).toBeInTheDocument();
    expect(next).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Previous page' }));
    expect(bodyNames()[0]).toBe('item-11');
  });

  it('searches case-insensitively and returns to page 1', async () => {
    const { user } = setup();
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    await user.type(screen.getByRole('searchbox'), 'ITEM-2');
    // item-2, item-20..item-29
    expect(bodyNames()).toHaveLength(10);
    expect(bodyNames()[0]).toBe('item-2');
    expect(screen.getByText('1–10 of 11')).toBeInTheDocument();
  });

  it('distinguishes "no match" (with a clear button) from an empty table', async () => {
    const { user } = setup();
    await user.type(screen.getByRole('searchbox'), 'zzz');
    expect(screen.getByText('Nothing matches “zzz”.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(screen.getByRole('searchbox')).toHaveValue('');
    expect(bodyNames()).toHaveLength(10);
  });

  it('renders the empty snippet only when there are no rows at all', () => {
    const empty = createRawSnippet(() => ({ render: () => '<p>No items yet</p>' }));
    setup({ rows: [], empty });
    expect(screen.getByText('No items yet')).toBeInTheDocument();
    expect(screen.queryByText(/Nothing matches/)).not.toBeInTheDocument();
  });

  it('shows skeleton rows while loading with no data', () => {
    const { container } = setup({ rows: [], loading: true });
    expect(container.querySelectorAll('tr.dt-skel')).toHaveLength(5);
  });

  it('sorts by a column, toggling direction, with aria-sort', async () => {
    const { user } = setup();
    const sizeHeader = screen.getByRole('columnheader', { name: /Size/ });
    expect(sizeHeader).toHaveAttribute('aria-sort', 'none');
    expect(screen.getByRole('columnheader', { name: 'Note' })).not.toHaveAttribute('aria-sort');

    await user.click(within(sizeHeader).getByRole('button'));
    expect(sizeHeader).toHaveAttribute('aria-sort', 'ascending');
    const sizes = (names: (string | null | undefined)[]) => names.map((n) => rows.find((r) => r.name === n)!.size);
    expect(sizes(bodyNames())).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    await user.click(within(sizeHeader).getByRole('button'));
    expect(sizeHeader).toHaveAttribute('aria-sort', 'descending');
    expect(sizes(bodyNames())[0]).toBe(29);
  });

  it('sorts names numerically ("item-2" before "item-10")', async () => {
    const { user } = setup({ pageSize: 50 });
    await user.click(within(screen.getByRole('columnheader', { name: /Name/ })).getByRole('button'));
    expect(bodyNames().slice(0, 3)).toEqual(['item-1', 'item-2', 'item-3']);
  });

  it('selects rows, selects the visible page, and shows bulk actions', async () => {
    const bulk = createRawSnippet((sel: () => string[]) => ({
      render: () => `<span data-testid="bulk">${sel().join(',')}</span>`
    }));
    const { user } = setup({ selectable: true, bulk });
    const boxes = screen.getAllByRole('checkbox', { name: 'Select row' });
    await user.click(boxes[0]);
    await user.click(boxes[2]);
    expect(screen.getByRole('region', { name: 'Bulk actions' })).toHaveTextContent('2 selected');
    expect(boxes[0]).toBeChecked();

    const all = screen.getByRole('checkbox', { name: 'Select all on this page' });
    await user.click(all);
    expect(screen.getByRole('region', { name: 'Bulk actions' })).toHaveTextContent('10 selected');
    expect(all).toBeChecked();

    // Selection survives paging; the header box reflects the visible page only.
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(screen.getByRole('checkbox', { name: 'Select all on this page' })).not.toBeChecked();
    await user.click(screen.getAllByRole('checkbox', { name: 'Select row' })[0]);
    expect(screen.getByRole('region', { name: 'Bulk actions' })).toHaveTextContent('11 selected');

    await user.click(screen.getByRole('button', { name: 'Clear' }));
    expect(screen.queryByRole('region', { name: 'Bulk actions' })).not.toBeInTheDocument();
  });

  it('hides the search box when not searchable', () => {
    setup({ searchable: undefined });
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
  });
});
