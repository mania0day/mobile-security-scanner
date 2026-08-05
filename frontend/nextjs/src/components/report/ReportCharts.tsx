'use client';

import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Legend,
} from 'recharts';
import { categoryLabel, riskColor } from '@/components/report/ScoreRing';
import { ChecklistItem, AppFinding } from '@/lib/api';

const TOOLTIP_STYLE = {
  background: '#fff',
  border: '1px solid #E5E7EB',
  borderRadius: 10,
  fontSize: 12,
  boxShadow: '0 4px 16px rgba(0,0,0,0.08)',
  padding: '8px 12px',
};

export function RiskDistributionChart({ apps }: { apps: AppFinding[] }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const a of apps) {
    const k = (a.risk_level || 'LOW').toUpperCase() as keyof typeof counts;
    if (k in counts) counts[k] += 1;
    else counts.LOW += 1;
  }
  const data = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  if (!data.length) {
    return (
      <div className="flex h-52 items-center justify-center">
        <p className="text-sm text-muted">No app risk data available</p>
      </div>
    );
  }

  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={56}
            outerRadius={82}
            paddingAngle={3}
            stroke="none"
            isAnimationActive
            animationBegin={0}
            animationDuration={900}
            animationEasing="ease-out"
          >
            {data.map((d) => (
              <Cell key={d.name} fill={riskColor(d.name)} />
            ))}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Legend
            iconType="circle"
            iconSize={8}
            formatter={(value) => <span style={{ fontSize: 11, color: '#6B7280' }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function CategoryHealthChart({ checklist }: { checklist: ChecklistItem[] }) {
  const map = new Map<string, { pass: number; warn: number; fail: number }>();
  for (const item of checklist) {
    const key = item.category || 'other';
    const row = map.get(key) || { pass: 0, warn: 0, fail: 0 };
    if (item.status === 'FAIL') row.fail += 1;
    else if (item.status === 'WARNING') row.warn += 1;
    else row.pass += 1;
    map.set(key, row);
  }

  const data = [...map.entries()].map(([key, v]) => {
    const total = v.pass + v.warn + v.fail || 1;
    const health = Math.round(((v.pass * 100) + (v.warn * 40)) / total);
    return {
      name: categoryLabel(key),
      health,
      fail: v.fail,
      warn: v.warn,
      pass: v.pass,
    };
  });

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 0, right: 20, top: 4, bottom: 4 }}>
          <XAxis type="number" domain={[0, 100]} hide />
          <YAxis
            type="category"
            dataKey="name"
            width={110}
            tick={{ fontSize: 11, fill: '#6B7280' }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            formatter={(value: number, _n, props) => {
              const p = props?.payload;
              return [`${value}% — ${p?.pass || 0}P / ${p?.warn || 0}W / ${p?.fail || 0}F`, 'Health'];
            }}
          />
          <Bar
            dataKey="health"
            radius={[0, 6, 6, 0]}
            barSize={12}
            isAnimationActive
            animationDuration={700}
            animationEasing="ease-out"
          >
            {data.map((d) => (
              <Cell
                key={d.name}
                fill={d.health < 50 ? '#DC2626' : d.health < 80 ? '#D97706' : '#16A34A'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TopAppsChart({ apps }: { apps: AppFinding[] }) {
  const data = [...apps]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 8)
    .map((a) => ({
      name: (a.package_name || '').split('.').slice(-2).join('.') || a.package_name,
      full: a.package_name,
      score: a.risk_score,
      level: a.risk_level,
    }));

  if (!data.length) {
    return (
      <div className="flex h-48 items-center justify-center">
        <p className="text-sm text-muted">No elevated-risk apps detected</p>
      </div>
    );
  }

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 0, right: 20, top: 4, bottom: 4 }}>
          <XAxis type="number" domain={[0, 100]} hide />
          <YAxis
            type="category"
            dataKey="name"
            width={130}
            tick={{ fontSize: 10, fill: '#6B7280', fontFamily: 'ui-monospace' }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            formatter={(value: number, _n, props) => [`${value} (${props?.payload?.level})`, props?.payload?.full]}
          />
          <Bar
            dataKey="score"
            radius={[0, 6, 6, 0]}
            barSize={11}
            isAnimationActive
            animationDuration={800}
            animationEasing="ease-out"
          >
            {data.map((d) => (
              <Cell key={d.full} fill={riskColor(d.level)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
