#ifndef ZNODE_H
#define ZNODE_H
#include <vector>

#include "gamez/zRender/zrender.h"
#include "gamez/zIntersect/zintersect.h"
#include "gamez/zVisual/zvis.h"
#include "gamez/zTexture/ztex.h"

#define MAX_NUM_CELL_ATOMS 1600

/// -------------------------------------------
/// FORWARD DECLARATIONS
/// -------------------------------------------
class CMaterial_Object;
class CZProjectile;
class CValve;

namespace zdb
{
	struct tag_NODE_PARAMS;
	struct IntersectStruct;
	
	class CNode;
	class CNodeEx;

	class CGridAtom;
	class CCell;
	class COrderedCell;

	class CSaveLoad;
	class CModel;
	class CAssetLib;

	class CNodeUniverse;
	class CWorld;
	class CAppCamera;
	class CGrid;

	class CVisual;
	class CMesh;
	class CSubMesh;

	class CTexture;
	class CTexHandle;

	class CAssetLib;

	class CDI;
}

struct _cellData
{
	u32 offPntNorm[2];
	u32 offUV[2];
	u32 offColor[2];
};

namespace zdb
{
	extern u32 numNodes;

	extern CNodeUniverse* NodeUniverse;
	extern CWorld* theWorld;

	struct _globalLight
	{
		CPnt4D dir[3];
		CPnt4D col[3];
		CPnt4D ambient;
	};

	struct tag_NODE_PARAMS
	{
		CMatrix m_matrix;
		CBBox m_bbox;
		u32 m_type;
		u32 m_active : 1;
		u32 m_dynamic_motion : 1;
		u32 m_dynamic_light : 1;
		u32 m_landmark : 1;
		u32 m_light : 1;
		u32 m_prelight : 1;
		u32 m_fog : 1;
		u32 m_transparent : 1;
		u32 m_facade : 2;
		u32 m_reflective : 1;
		u32 m_bumpmap : 1;
		u32 m_hasDI : 1;
		u32 m_region_shift : 5;
		u32 m_has_visuals_prior_to_export : 1;
		u32 m_shadow : 1;
		u32 m_worldchild : 1;
		u32 m_char_common : 1;
		u32 m_NOTUSED : 1;
		u32 m_hasVisuals : 1;
		u32 m_hasMesh : 1;
		u32 m_scrolling_texture : 1;
		u32 m_light_dynamic : 1;
		u32 m_light_static : 1;
		u32 m_clutter : 1;
		u32 m_mtx_is_identity : 1;
		u32 m_use_parent_bbox : 1;
		u32 m_apply_clip : 1;
	};

	void InitNodeParams(tag_NODE_PARAMS* nparams, const tag_NODE_PARAMS* other = NULL);

	struct tag_GRID_PARAMS
	{
		struct tag_SIZE
		{
			s32 cx;
			s32 cy;
		};

		s32 m_AtomCnt;
		s32 m_posts;
		f32 m_CellDim;
		tag_SIZE m_CellCount;
	};

	class CNodeVector : public std::vector<CNode*>
	{
	public:
		bool Exists(const CNode* node) const;
		bool Remove(const CNode* node);
		CNode* GetNode(const char* name) const;
	};

	class CNode : public tag_NODE_PARAMS
	{
		friend class CNodeVector;
		friend class CWorld;
	public:
		// TODO:
		// guess the rest of these
		enum class TYPE
		{
			EMPTY,
			GENERIC,
			INSTANCE,
			CHILD,
			MULTI_PARENT,
			UNK5,
			GRID,
			MODEL,
			LIGHT,
			LENSFLARE,
			CELL
		};
		
		CNode();

		static CNode* CreateInstance(CSaveLoad& sload);
		static CNode* CreateInstance(const char* name, const CPnt3D* position, const CQuat* rotation);
		static CNode* CreateInstance(CModel* model, const CPnt3D* position, const CQuat* rotation);
		
		static CNode* CreateXRef();
		static CNode* CreateXRef(CModel* model, const CPnt3D* position, const CQuat* rotation);

		CNode* Create(const char* name);

		static CNode* Read(CSaveLoad& sload, CNode* node);
		virtual bool Read(CSaveLoad& sload);
		bool ReadDataBegin(CSaveLoad& sload);
		CNode* Copy();
		CNode* _Copy(CNode* other);
		bool Delete();
		
		void AddChild(CNode* child);
		s32 DeleteChild(CNode* child);
		void DeleteChildren();
		void RemoveFromParent() {}

		CGridAtom* GetAtom(s16 index);
		void InsertAtom(CGridAtom* atom);
		void FreeAtom();
		bool UpdateGrid();
		void ShrinkAtomBasePtrs();
		void SetAtomCnt(u16 count);
		void AllocateAtomBasePtrs(s32 x, s32 y);

		CNode* FindChild(CNode* child, bool nested);
		CNode* FindChild(const char* child, bool nested);

		CMatrix& BuildMTW(CMatrix& mat);

		void ReserveChildren(size_t size);
		void ReserveDI(size_t size);
		void ReserveVisuals(size_t size);

		bool AddVisual(CVisual* visual);
		bool AddDI(CDI* di);
		bool DeleteVisual(CVisual* visual, bool doChildren);
		
		s32 DeleteVisuals();

		void ComputeFacadeMatrix(const CMatrix* view, CMatrix* model);

		void SetParentHasVisuals();
		void SetDynamicLight(bool self_light, bool apply_to_children);

		bool InheritRegionMasks(u32 pmask, u32 cmask);

		virtual s16 Release();
		bool Rendered();
		
		/// -------------------------------------------
		/// GETTERS/SETTERS
		/// -------------------------------------------

		void SetMatrix(const CMatrix* matrix);
		void SetPosition(f32 x, f32 y, f32 z);
		void SetRotation(const CQuat* rotation) {};
		void SetScale(f32 scaleFactor);
		void SetScale(CPnt3D* scale);

		void TransformToWorld(const CPnt3D& point);
		
		CPnt3D* GetRotation(const CPnt3D* rotation) const;
		CPnt3D* GetScale(CPnt3D* scale) const;
		f32 GetScale() const;
		
		f32 GetRadius() const;
		f32 GetRadiusSq() const;

		CBBox* GetBBox();
		
		CMesh* GetMesh() const;
		CSubMesh* GetSubMesh() const { return NULL; }

		bool SetActive(bool active);
		void SetName(const char* name);
		bool SetModel(CModel* model);
		void SetModelname(const char* name);

		CNode* m_parent;
		CNodeVector m_child;
		CDIVector m_di;
		CVisualVector m_visual;
		char* m_name;
		CNodeEx* m_nodeEx;
		s8 m_customGlobalLight;
		bool m_frameRendered;
		u16 m_flatten : 1;
		u16 m_modified : 1;
		u16 m_character : 1;
		u16 m_character_infov : 1;
		u16 m_unused : 12;
		f32 m_Opacity;
		CGridAtom** m_Atom;
		s32 m_TickNum;
		s16 m_AtomCnt;
		s16 m_AtomAlloc;
		s16 m_count;
		s16 m_vid;
		CModel* m_model;
		char* m_modelname;
		u32 m_region_mask;
	};

	class CNodeEx : public CNode
	{
	public:
		virtual void OnAction(CNode* node, void* action) {}
		virtual void OnCopy(CNode* node, CNode* other) {}
		virtual void OnDelete(CNode* node) {}
		virtual void OnDoubleClick(CNode* node) {}
		virtual void OnMove(CNode* node) {}
		virtual void OnSelect(CNode* node, bool selected) {}
		virtual void OnWeaponHit(CNode* node, IntersectStruct* intersection, CZProjectile* projectile) {}

	public:
		class CEntity* m_entity;
	};
}
#endif