#include <metal_stdlib>
using namespace metal;
struct VSU { float4x4 m; float4 vp; float minz, maxz, width, height; uint stride, diffuse, specular, ntex; uint tex[8];
             uint xyz, pad0, pad1, pad2; };
struct StageU { uint cop, ca1, ca2, ca0, aop, aa1, aa2, aa0, tci, result, hastex, pad; };
struct FSU { float4 tfactor; float4 fogcolor; uint fog, atest, afunc, aref; StageU st[8]; };
struct ClearU { float4 rect; float4 color; float z; float3 pad; };
struct V2F {
    float4 pos [[position]];
    float4 dif; float4 spe;
    float2 t0; float2 t1; float2 t2; float2 t3; float2 t4; float2 t5; float2 t6; float2 t7;
};

static float4 argb(uint c) {
    return float4(float((c >> 16) & 255u), float((c >> 8) & 255u), float(c & 255u), float(c >> 24)) / 255.0;
}

// D3D pre-transformed vertex: x, y in pixels (pixel centres at integers), z in [0,1], rhw = 1/w.
// Untransformed vertex: clip = (x, y, z, 1) x World x View x Projection, then D3D's viewport mapping
// (NDC -1 -> pixel centre X) gives the same screen-space x, y, z and w = clip w.
vertex V2F vs_main(device const uint *vb [[buffer(0)]], constant VSU &u [[buffer(1)]], uint vid [[vertex_id]]) {
    device const uint *v = vb + vid * u.stride;
    float x = as_type<float>(v[0]), y = as_type<float>(v[1]), z = as_type<float>(v[2]), w;
    if (u.xyz != 0u) {
        float4 c = u.m * float4(x, y, z, 1.0);
        w = c.w;
        float iw = 1.0 / c.w;
        x = u.vp.x + (1.0 + c.x * iw) * u.vp.z * 0.5;
        y = u.vp.y + (1.0 - c.y * iw) * u.vp.w * 0.5;
        z = u.minz + c.z * iw * (u.maxz - u.minz);
    } else {
        float rhw = as_type<float>(v[3]);
        w = (rhw > 0.0 && isfinite(1.0 / rhw)) ? 1.0 / rhw : 1.0;
    }
    float nx = (x + 0.5) / u.width * 2.0 - 1.0;          // Metal pixel centres are at +0.5
    float ny = 1.0 - (y + 0.5) / u.height * 2.0;
    V2F o;
    o.pos = float4(nx * w, ny * w, z * w, w);
    o.dif = u.diffuse != 0xFFFFFFFFu ? argb(v[u.diffuse]) : float4(1.0);
    o.spe = u.specular != 0xFFFFFFFFu ? argb(v[u.specular]) : float4(0.0, 0.0, 0.0, 1.0);
    float2 t[8];
    for (uint i = 0; i < 8; i++)
        t[i] = i < u.ntex ? float2(as_type<float>(v[u.tex[i]]), as_type<float>(v[u.tex[i] + 1])) : float2(0.0);
    o.t0 = t[0]; o.t1 = t[1]; o.t2 = t[2]; o.t3 = t[3]; o.t4 = t[4]; o.t5 = t[5]; o.t6 = t[6]; o.t7 = t[7];
    return o;
}

static float4 sel_arg(uint a, float4 dif, float4 cur, float4 tx, float4 tf, float4 spe, float4 temp) {
    float4 s;
    switch (a & 15u) {
        case 0: s = dif; break;  case 1: s = cur; break;  case 2: s = tx; break;
        case 3: s = tf; break;   case 4: s = spe; break;  case 5: s = temp; break;
        default: s = cur; break;
    }
    if (a & 0x20u) s = float4(s.a);
    if (a & 0x10u) s = 1.0 - s;
    return s;
}

static float4 tex_op(uint op, float4 a1, float4 a2, float4 a0, float4 dif, float4 tx, float4 cur, float4 tf) {
    switch (op) {
        case 2: return a1;
        case 3: return a2;
        case 4: return a1 * a2;
        case 5: return saturate(a1 * a2 * 2.0);
        case 6: return saturate(a1 * a2 * 4.0);
        case 7: return saturate(a1 + a2);
        case 8: return saturate(a1 + a2 - 0.5);
        case 9: return saturate((a1 + a2 - 0.5) * 2.0);
        case 10: return saturate(a1 - a2);
        case 11: return saturate(a1 + a2 - a1 * a2);
        case 12: return mix(a2, a1, dif.a);
        case 13: return mix(a2, a1, tx.a);
        case 14: return mix(a2, a1, tf.a);
        case 15: return saturate(a1 + a2 * (1.0 - tx.a));
        case 16: return mix(a2, a1, cur.a);
        case 24: return float4(saturate(dot(a1.rgb - 0.5, a2.rgb - 0.5) * 4.0));
        case 25: return saturate(a0 + a1 * a2);
        case 26: return a0 * a1 + (1.0 - a0) * a2;
        default: return a1;
    }
}

static bool cmp(uint f, float a, float b) {
    switch (f) {
        case 1: return false;    case 2: return a < b;   case 3: return a == b;  case 4: return a <= b;
        case 5: return a > b;    case 6: return a != b;  case 7: return a >= b;  default: return true;
    }
}

fragment float4 fs_main(V2F in [[stage_in]], constant FSU &u [[buffer(0)]],
                        array<texture2d<float>, 8> tex [[texture(0)]], array<sampler, 8> smp [[sampler(0)]]) {
    float2 tc[8] = { in.t0, in.t1, in.t2, in.t3, in.t4, in.t5, in.t6, in.t7 };
    float4 dif = in.dif, spe = in.spe, cur = in.dif, temp = float4(0.0), tf = u.tfactor;
    for (uint s = 0; s < 8; s++) {
        StageU st = u.st[s];
        if (st.cop == 1u) break;
        float4 tx = st.hastex ? tex[s].sample(smp[s], tc[st.tci & 7u]) : float4(0.0, 0.0, 0.0, 1.0);
        float4 c = tex_op(st.cop, sel_arg(st.ca1, dif, cur, tx, tf, spe, temp), sel_arg(st.ca2, dif, cur, tx, tf, spe, temp),
                          sel_arg(st.ca0, dif, cur, tx, tf, spe, temp), dif, tx, cur, tf);
        float a = st.aop == 1u ? cur.a :
                  tex_op(st.aop, sel_arg(st.aa1, dif, cur, tx, tf, spe, temp), sel_arg(st.aa2, dif, cur, tx, tf, spe, temp),
                         sel_arg(st.aa0, dif, cur, tx, tf, spe, temp), dif, tx, cur, tf).a;
        float4 res = float4(c.rgb, a);
        if (st.result == 5u) temp = res; else cur = res;
    }
    if (u.fog != 0u) cur.rgb = mix(u.fogcolor.rgb, cur.rgb, spe.a);
    if (u.atest != 0u && !cmp(u.afunc, round(saturate(cur.a) * 255.0), float(u.aref & 255u))) discard_fragment();
    return saturate(cur);
}

// Profiling variants (MPR_PROFILE=flatfs / tex1): the vertex colour only; stage 0's texture times the vertex colour.
fragment float4 fs_flat(V2F in [[stage_in]]) { return saturate(in.dif); }
fragment float4 fs_tex1(V2F in [[stage_in]], texture2d<float> t0 [[texture(0)]], sampler s0 [[sampler(0)]]) {
    return saturate(t0.sample(s0, in.t0) * in.dif);
}

// Clears: a full-target triangle limited by the scissor rectangle.
struct ClearOut { float4 pos [[position]]; };
vertex ClearOut clear_vs(constant ClearU &u [[buffer(0)]], uint vid [[vertex_id]]) {
    float2 p = float2((vid << 1) & 2u, vid & 2u) * 2.0 - 1.0;
    ClearOut o; o.pos = float4(p, u.z, 1.0); return o;
}
fragment float4 clear_fs(constant ClearU &u [[buffer(0)]]) { return u.color; }
