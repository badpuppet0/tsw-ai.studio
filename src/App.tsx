/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

export default function App() {
  return (
    <div className="min-h-screen bg-[#020308] text-[#d5dcec] flex flex-col items-center justify-center p-6 text-center select-none font-sans">
      <div className="w-full max-w-lg bg-[#0b0e17] border border-[#1b2130] rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Ambient subtle glow */}
        <div className="absolute -top-12 -right-12 w-32 h-32 bg-[#5aa2ff]/10 rounded-full blur-2xl pointer-events-none" />

        <div className="text-3xl font-light tracking-[0.25em] text-white mb-2">
          TSW<span className="font-semibold text-[#5aa2ff] text-xl ml-1 tracking-normal">v2</span>
        </div>

        <div className="w-16 h-0.5 bg-[#5aa2ff] mx-auto my-4 rounded-full opacity-80" />

        <h1 className="text-lg font-medium text-white mb-2">Workspace Cleared & Ready</h1>
        <p className="text-sm text-[#6b7488] leading-relaxed mb-6">
          All previous components have been deleted. Ready to insert the Scramjet proxy from GitHub.
        </p>

        <div className="p-3.5 rounded-xl bg-[#020308] border border-[#1b2130] font-mono text-xs text-[#5aa2ff] flex items-center justify-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-[#5aa2ff] animate-ping" />
          <span>Awaiting Scramjet proxy GitHub repository link...</span>
        </div>
      </div>
    </div>
  );
}
