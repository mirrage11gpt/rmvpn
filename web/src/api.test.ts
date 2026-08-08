import {afterEach,describe,expect,it,vi} from 'vitest'
import {ApiError,api} from './api'

afterEach(()=>vi.unstubAllGlobals())

describe('api errors',()=>{
  it('preserves status and problem details',async()=>{
    vi.stubGlobal('document',{cookie:'rvpn_csrf=csrf-token'})
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({type:'urn:risevpn:problem:node-claim',title:'Узел не подключён',detail:'claim returned HTTP 503'}),{status:502,headers:{'Content-Type':'application/problem+json'}})))

    const request=api('/admin/nodes/enroll',{method:'POST',body:'{}'})
    await expect(request).rejects.toMatchObject({status:502,type:'urn:risevpn:problem:node-claim',message:'claim returned HTTP 503'} satisfies Partial<ApiError>)
  })

  it('adds CSRF to mutating requests',async()=>{
    vi.stubGlobal('document',{cookie:'other=value; rvpn_csrf=csrf-token'})
    const fetchMock=vi.fn().mockResolvedValue(new Response(null,{status:204}))
    vi.stubGlobal('fetch',fetchMock)

    await api('/admin/nodes/enroll',{method:'POST',body:'{}'})
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/admin/nodes/enroll',expect.objectContaining({headers:expect.objectContaining({'X-CSRF-Token':'csrf-token'})}))
  })
})
