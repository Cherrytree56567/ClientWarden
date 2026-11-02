import CursorGrid from './components/CursorGrid';
import TechText from './components/TechText';

function App() {
  return (
    <div className="min-h-screen bg-ctp-crust text-ctp-text">
      <div className="border-b border-ctp-surface0">
        <div className="navbar mx-auto max-w-6xl px-6">
          <div className="navbar-start">
            <a className="text-xl font-bold text-ctp-text">ClientWarden</a>
          </div>

          <div className="navbar-end gap-2">
            <a className="btn btn-ghost font-normal text-ctp-subtext1">GitHub</a>
            <a className="btn border-0 rounded-full bg-ctp-lavender text-ctp-base">Download</a>
          </div>
        </div>
      </div>

      <div style={{ width: '100%', height: '100%', position: 'fixed' }}>
        <CursorGrid
          cellSize={20}
          color="#cdd6f4"
          highlight="area"
          gridStyle="dashed"
          radius={70}
          holdTime={400}
          fadeDuration={800}
          fillOpacity={0.1}
          gridOpacity={0.1}
          spotlight={0.6}
          maxOpacity={0.5}
          intro={false}
          ambient={0.1}
          edgeFade={0.05}
          clickPulse>
          <TechText
            text="ClientWarden"
            fontWeight={600}
            fontSize={150}
            reveal="letter"
            dashLength={4}
            dashGap={2}
            specks={15}
            intro="metrics"
            introDuration={2}
            clickKick
            guides={false}
            fontFamily=""
            letterSpacing={-0.05}
            accentColor="#cdd6f4"
            reach={200}
            softness={0.7}
            lineStyle="dashed"
            strokeWidth={1.5}
            speed={1}
            bounce={0.4}
            selection
            labels
            color="#cdd6f4"
            align="center"
            draggable
            sweep/>
        </CursorGrid>
      </div>
    </div>
  )
}

export default App
