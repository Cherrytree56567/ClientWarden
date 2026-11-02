import CursorGrid from './components/CursorGrid';
import TechText from './components/TechText';
import SpecularButton from './components/SpecularButton';
import { FaGithub } from 'react-icons/fa';

function App() {
  return (
    <div className="min-h-screen bg-ctp-crust text-ctp-text">
      <div className="relative z-10 border-b border-ctp-surface0">
        <div className="navbar mx-auto max-w-6xl px-6">
          <div className="navbar-start">
            <img src="ic_launcher.png" className="h-8 w-8"></img>
            &nbsp;&nbsp;
            <a className="text-xl font-bold text-ctp-text">ClientWarden</a>
          </div>

          <div className="navbar-end gap-2">
            <a className="btn btn-ghost font-normal text-ctp-subtext1" href="https://github.com/Cherrytree56567/ClientWarden">GitHub</a>
            <a className="btn border-0 rounded-full bg-ctp-lavender text-ctp-base" href="https://github.com/Cherrytree56567/ClientWarden/releases">Download</a>
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
          <div className="flex h-full flex-col">
            <div className="min-h-0 flex-1">
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
            </div>
            <div className="flex flex-col items-center gap-6 px-6 pb-24">
              <h1 className="mx-auto max-w-2xl px-6 pb-32 text-center text-xl text-ctp-subtext1">
                <p className="max-w-2xl text-balance text-center text-xl text-ctp-subtext1">
                  A beautifully designed password manager that's designed around security and privacy.
                </p>
                <br></br><br></br>
                <div className="flex items-center justify-center gap-4">
                  <SpecularButton
                    size="md"
                    radius={18}
                    tint="#89b4fa"
                    tintOpacity={0.04}
                    textColor="#f5f5f5"
                    lineColor="#ffffff"
                    baseColor="#525252"
                    intensity={1}
                    idleIntensity={0.35}
                    shineSize={10}
                    shineFade={34}
                    thickness={1.2}
                    glow={1}
                    followMouse={false}
                    proximity={250}
                    autoAnimate={true}
                    blur={2}
                    onClick={() => window.open('https://github.com/Cherrytree56567/ClientWarden/releases', '_blank', 'noopener,noreferrer')}>
                    Download
                  </SpecularButton>
                  <SpecularButton
                    size="md"
                    radius={18}
                    tint="#ffffff"
                    tintOpacity={0.04}
                    textColor="#f5f5f5"
                    lineColor="#ffffff"
                    baseColor="#525252"
                    intensity={1}
                    idleIntensity={0.35}
                    shineSize={10}
                    shineFade={34}
                    thickness={1.2}
                    glow={1}
                    followMouse
                    proximity={250}
                    blur={2}
                    onClick={() => window.open('https://github.com/Cherrytree56567/ClientWarden', '_blank', 'noopener,noreferrer')}>
                    <span className="flex items-center gap-2">
                      <FaGithub size={20} />
                      GitHub
                    </span>
                  </SpecularButton>
                </div>
              </h1>
              <p className="pb-4 text-center text-xs text-ctp-overlay1">
                Made by <a href="mailto:ct5@clientwarden.app" className="text-ctp-lavender">@CT5</a> - No AI was used in this project!
              </p>
            </div>
          </div>
        </CursorGrid>
      </div>
    </div>
  )
}

export default App
