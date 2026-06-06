"use client"

import { useMemo } from "react"
import { motion } from "framer-motion"

export default function DarkWebSVG() {
  const { points, radialLines, webLines, randomLinks } = useMemo(() => {
    const pts = []
    const rads = []
    const webs = []
    const rnds = []
    
    // Config
    const numAxes = 14
    const numLayers = 10
    const centerX = 500
    const centerY = 450 // slightly offset from pure center
    const maxRadius = 900 // Overflows the 1000x1000 viewBox to cover corners
    
    // Generate Nodes
    for (let a = 0; a < numAxes; a++) {
      const baseAngle = (a / numAxes) * Math.PI * 2
      for (let l = 1; l <= numLayers; l++) {
        // Logarithmic-styled spacing (closer near center, wider farther out)
        const radiusExp = Math.pow(l / numLayers, 1.2)
        const radius = radiusExp * maxRadius
        
        // Add organic jitter to make it look like a real web / mesh
        const angleJitter = (Math.random() - 0.5) * 0.15
        const angle = baseAngle + angleJitter
        
        const x = centerX + Math.cos(angle) * radius
        const y = centerY + Math.sin(angle) * radius
        
        pts.push({ x, y, a, l, isKeyNode: Math.random() > 0.85 })
      }
    }

    // Radial Lines (Structural threads of the web)
    for (let a = 0; a < numAxes; a++) {
      const outermost = pts.find(p => p.a === a && p.l === numLayers)
      if (outermost) {
        rads.push({ x1: centerX, y1: centerY, x2: outermost.x, y2: outermost.y })
      }
    }

    // Spiral/Web Lines (Connecting threads)
    for (let l = 1; l <= numLayers; l++) {
      for (let a = 0; a < numAxes; a++) {
        const p1 = pts.find(p => p.a === a && p.l === l)
        const p2 = pts.find(p => p.a === (a + 1) % numAxes && p.l === l)
        // Ensure some threads are "broken" for a dark/hacked vibe
        if (p1 && p2 && Math.random() > 0.1) {
          webs.push({ x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y })
        }
      }
    }

    // Random cross-links (The "Dark Web" chaos)
    for(let i = 0; i < 40; i++) {
        const idx1 = Math.floor(Math.random() * pts.length)
        let idx2 = Math.floor(Math.random() * pts.length)
        
        const p1 = pts[idx1]
        const p2 = pts[idx2]
        
        // Only connect nearby layers to avoid messy spaghetti
        if (Math.abs(p1.l - p2.l) <= 2) {
            rnds.push({ x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y })
        }
    }

    return { points: pts, radialLines: rads, webLines: webs, randomLinks: rnds }
  }, [])

  return (
    <div className="w-full h-full flex items-center justify-center relative overflow-hidden select-none pointer-events-none">
      
      {/* Background illumination for depth */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-[var(--accent)]/5 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute top-[40%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[300px] h-[300px] bg-indigo-500/10 blur-[80px] rounded-full pointer-events-none" />

      {/* Adding responsive scaling so it covers the entire right panel beautifully */}
      <svg 
        viewBox="0 0 1000 1000" 
        className="w-full h-full min-w-[1200px] min-h-[1200px] max-w-none opacity-80"
        preserveAspectRatio="xMidYMid slice"
        xmlns="http://www.w3.org/2000/svg"
        style={{ transform: "translate(10%, -5%)" }} // Shift slightly off-center for asymmetry
      >
        <defs>
          <linearGradient id="radialGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#1c1c21" stopOpacity="0" />
          </linearGradient>
          
          <radialGradient id="glowFX" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="1" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* 1. Structural Radials */}
        {radialLines.map((line, i) => (
          <motion.line 
            key={`rad-${i}`}
            x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2}
            stroke="url(#radialGrad)"
            strokeWidth="1.5"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.5 }}
            transition={{ duration: 2, ease: "easeOut", delay: i * 0.1 }}
          />
        ))}

        {/* 2. Web Spirals connecting the radials */}
        {webLines.map((line, i) => (
          <motion.line 
            key={`web-${i}`}
            x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2}
            stroke="var(--accent)"
            strokeWidth="1"
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.3 }}
            transition={{ duration: 1.5, delay: 1 + (i % 30) * 0.05 }}
          />
        ))}

        {/* 3. Anomalous "Dark Web" data links */}
        {randomLinks.map((line, i) => (
          <motion.line 
            key={`rnd-${i}`}
            x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2}
            stroke="#8b949e"
            strokeWidth="0.5"
            strokeDasharray="4 4"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.4 }}
            transition={{ duration: 2, delay: 2 + i * 0.1 }}
          />
        ))}

        {/* 4. Intersection Nodes */}
        {points.map((p, i) => (
            <g key={`node-${i}`}>
                {/* Base intersection dot */}
                <motion.circle 
                    cx={p.x} cy={p.y} r={p.isKeyNode ? 4 : 2} 
                    fill="#18181b"
                    stroke="var(--accent)"
                    strokeWidth="1"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1, opacity: p.isKeyNode ? 1 : 0.6 }}
                    transition={{ type: "spring", delay: 1.5 + (i % 20) * 0.05 }}
                />
                
                {/* Pulsing glow on Key Nodes */}
                {p.isKeyNode && (
                    <motion.circle 
                        cx={p.x} cy={p.y} r="12" 
                        fill="url(#glowFX)"
                        opacity="0.5"
                        animate={{ opacity: [0.1, 0.7, 0.1], scale: [0.8, 1.2, 0.8] }}
                        transition={{ duration: 3 + Math.random() * 2, repeat: Infinity, ease: "easeInOut", delay: Math.random() * 2 }}
                    />
                )}
            </g>
        ))}

        {/* Core Origin Point */}
        <motion.circle 
            cx="500" cy="450" r="16" 
            fill="#080b0f"
            stroke="var(--accent)"
            strokeWidth="2"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ duration: 1, type: "spring" }}
        />
        <motion.circle 
            cx="500" cy="450" r="24" 
            fill="none"
            stroke="var(--accent)"
            strokeWidth="1"
            strokeDasharray="2 6"
            animate={{ rotate: 360 }}
            transition={{ duration: 30, repeat: Infinity, ease: "linear" }}
            style={{ transformOrigin: "500px 450px" }}
        />

      </svg>
    </div>
  )
}
