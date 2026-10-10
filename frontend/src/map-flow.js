// Representative points from each country's largest mainland polygon.
// These indicate country-level attribution, never individual IP locations.
export function countryPoints(features) {
  const points = {};
  for (const feature of features) {
    const polygons =
      feature.geometry.type === "Polygon"
        ? [feature.geometry.coordinates]
        : feature.geometry.coordinates;
    let largest = 0;
    for (const polygon of polygons) {
      const ring = polygon[0];
      if (!ring?.length) continue;
      const unwrapped = [ring[0]];
      for (const [lon, lat] of ring.slice(1)) {
        let x = lon;
        const previous = unwrapped.at(-1)[0];
        while (x - previous > 180) x -= 360;
        while (x - previous < -180) x += 360;
        unwrapped.push([x, lat]);
      }
      let area = 0,
        x = 0,
        y = 0;
      for (let i = 0; i < unwrapped.length - 1; i++) {
        const a = unwrapped[i],
          b = unwrapped[i + 1];
        const cross = a[0] * b[1] - b[0] * a[1];
        area += cross;
        x += (a[0] + b[0]) * cross;
        y += (a[1] + b[1]) * cross;
      }
      if (Math.abs(area) <= largest) continue;
      largest = Math.abs(area);
      points[feature.properties.name] = [
        ((x / (3 * area) + 540) % 360) - 180,
        y / (3 * area),
      ];
    }
  }
  return points;
}

export const serverPoint = [116.4074, 39.9042];

// Split date-line polygons so their closing edges do not cross the entire map.
export function splitDateLine(features) {
  const clip = (ring, boundary, keepGreater) => {
    const result = [];
    for (let i = 0; i < ring.length; i++) {
      const a = ring[(i + ring.length - 1) % ring.length],
        b = ring[i];
      const inside = (p) => (keepGreater ? p[0] >= boundary : p[0] <= boundary);
      if (inside(a) !== inside(b)) {
        const fraction = (boundary - a[0]) / (b[0] - a[0]);
        result.push([boundary, a[1] + fraction * (b[1] - a[1])]);
      }
      if (inside(b)) result.push(b);
    }
    return result;
  };
  for (const feature of features) {
    const polygons =
      feature.geometry.type === "Polygon"
        ? [feature.geometry.coordinates]
        : feature.geometry.coordinates;
    const pieces = [];
    for (const polygon of polygons) {
      const rings = polygon.map((ring) => {
        const result = [ring[0]];
        for (const [lon, lat] of ring.slice(1)) {
          let x = lon;
          while (x - result.at(-1)[0] > 180) x -= 360;
          while (x - result.at(-1)[0] < -180) x += 360;
          result.push([x, lat]);
        }
        return result;
      });
      for (const offset of [-360, 0, 360]) {
        const clipped = rings.map((ring) =>
          clip(
            clip(
              ring.map(([x, y]) => [x + offset, y]),
              -180,
              true,
            ),
            180,
            false,
          ),
        );
        if (clipped[0].length < 3) continue;
        pieces.push(
          clipped
            .filter((ring) => ring.length >= 3)
            .map((ring) => [...ring, ring[0]]),
        );
      }
    }
    feature.geometry = { type: "MultiPolygon", coordinates: pieces };
  }
}
