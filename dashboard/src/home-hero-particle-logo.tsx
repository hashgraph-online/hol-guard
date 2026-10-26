import { useEffect, useRef } from "react";

import { brandMarkSvg } from "./brand-mark-geometry";
import { BRAND_NAVY, createParticleScene, type HeroParticleFinish, type HeroParticleMood, type ParticleScene } from "./home-hero-particles";
import { useReducedMotion } from "./use-reduced-motion";

export function HeroParticleLogo(props: {
  mood: HeroParticleMood;
  finish?: HeroParticleFinish;
  className?: string;
}) {
  const stageRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sceneRef = useRef<ParticleScene | null>(null);
  const reducedMotion = useReducedMotion();
  const finish = props.finish ?? "navy";

  const settingsRef = useRef({ finish, mood: props.mood, motion: !reducedMotion });
  settingsRef.current = { finish, mood: props.mood, motion: !reducedMotion };

  useEffect(() => {
    const stage = stageRef.current;
    const canvas = canvasRef.current;
    if (!stage || !canvas) return;
    let scene: ParticleScene | null = null;
    const teardown = (): void => {
      scene?.destroy();
      scene = null;
      sceneRef.current = null;
    };
    const build = (): void => {
      try {
        scene = createParticleScene(canvas, stage, () => {
          teardown();
          stage.classList.add("guard-hero-stage--fallback");
        });
      } catch {
        scene = null;
      }
      if (!scene) {
        stage.classList.add("guard-hero-stage--fallback");
        return;
      }
      stage.classList.remove("guard-hero-stage--fallback");
      const settings = settingsRef.current;
      scene.setFinish(settings.finish);
      scene.setMood(settings.mood);
      scene.setMotion(settings.motion);
      sceneRef.current = scene;
    };
    const onContextRestored = (): void => {
      teardown();
      build();
    };
    canvas.addEventListener("webglcontextrestored", onContextRestored);
    build();
    return () => {
      canvas.removeEventListener("webglcontextrestored", onContextRestored);
      teardown();
    };
  }, []);

  useEffect(() => {
    sceneRef.current?.setFinish(finish);
  }, [finish]);
  useEffect(() => {
    sceneRef.current?.setMood(props.mood);
  }, [props.mood]);
  useEffect(() => {
    sceneRef.current?.setMotion(!reducedMotion);
  }, [reducedMotion]);

  return (
    <div ref={stageRef} className={`guard-hero-stage${props.className ? ` ${props.className}` : ""}`} aria-hidden="true">
      <div className="guard-hero-halo" />
      <canvas ref={canvasRef} className="guard-hero-canvas" />
      <div className="guard-hero-fallback" dangerouslySetInnerHTML={{ __html: brandMarkSvg(finish === "white" ? "#ffffff" : BRAND_NAVY) }} />
    </div>
  );
}
